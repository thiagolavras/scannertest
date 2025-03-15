#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import sys
import time
import threading
import queue
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
    import tls_client
    from bs4 import BeautifulSoup
    from rich.console import Console
    from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn
    from colorama import Fore, Style, init
    from tqdm import tqdm
except ImportError:
    print("Erro: Dependências não instaladas. Execute 'pip install -r requirements.txt'")
    sys.exit(1)

# Inicializar colorama
init(autoreset=True)

# Console Rich para saídas formatadas
console = Console()

# Versão do scanner
VERSION = "1.0.0"

# Configurações globais
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0"
}

# Fila global para URLs
url_queue = queue.Queue()

# Conjunto de URLs já visitadas
visited_urls = set()

# Lock para operações thread-safe
url_lock = threading.Lock()
print_lock = threading.Lock()

# Banco de dados de vulnerabilidades (simulado)
from vulnerabilities.database import VULNERABILITY_DATABASE

class Scanner:
    def __init__(self, url, mode="requests", depth=3, threads=5, timeout=10, output="report.json"):
        self.base_url = url
        self.mode = mode
        self.max_depth = depth
        self.num_threads = threads
        self.timeout = timeout
        self.output_file = output
        
        # Garantir que a URL base tenha um esquema
        if not self.base_url.startswith(('http://', 'https://')):
            self.base_url = 'http://' + self.base_url
            
        # Extrair o domínio base
        parsed_url = urllib.parse.urlparse(self.base_url)
        self.base_domain = parsed_url.netloc
        
        # Inicializar cliente HTTP baseado no modo
        if self.mode == "tls_client":
            self.client = self._init_tls_client()
        else:
            self.client = requests.Session()
            self.client.headers.update(HEADERS)
        
        # Resultados
        self.vulnerabilities_found = []
        self.pages_scanned = 0
        self.start_time = None
        self.end_time = None

    def _init_tls_client(self):
        client = tls_client.Session(
            client_identifier="chrome112",
            random_tls_extension_order=True
        )
        client.headers.update(HEADERS)
        return client

    def make_request(self, url, method="GET", data=None, params=None, verify=True):
        try:
            if self.mode == "tls_client":
                if method.upper() == "GET":
                    response = self.client.get(url, params=params, timeout=self.timeout)
                elif method.upper() == "POST":
                    response = self.client.post(url, data=data, params=params, timeout=self.timeout)
                else:
                    response = self.client.request(method, url, data=data, params=params, timeout=self.timeout)
            else:
                if method.upper() == "GET":
                    response = self.client.get(url, params=params, timeout=self.timeout, verify=verify)
                elif method.upper() == "POST":
                    response = self.client.post(url, data=data, params=params, timeout=self.timeout, verify=verify)
                else:
                    response = self.client.request(method, url, data=data, params=params, timeout=self.timeout, verify=verify)
            
            return response
        except Exception as e:
            with print_lock:
                console.print(f"[bold red]Erro ao acessar {url}: {str(e)}[/bold red]")
            return None

    def is_same_domain(self, url):
        parsed_url = urllib.parse.urlparse(url)
        return parsed_url.netloc == self.base_domain or parsed_url.netloc == ""

    def normalize_url(self, url, base_url=None):
        if base_url is None:
            base_url = self.base_url
            
        # Lidar com URLs relativas
        if not url.startswith(('http://', 'https://')):
            url = urllib.parse.urljoin(base_url, url)
            
        # Remover fragmentos de URL
        parsed = urllib.parse.urlparse(url)
        url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ''))
        
        # Garantir que terminamos com / para URLs que apontam para diretórios
        if not parsed.path:
            url += '/'
            
        return url

    def extract_links(self, html, base_url):
        links = set()
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for anchor in soup.find_all('a', href=True):
                href = anchor['href']
                if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    normalized_url = self.normalize_url(href, base_url)
                    if self.is_same_domain(normalized_url):
                        links.add(normalized_url)
        except Exception as e:
            with print_lock:
                console.print(f"[bold yellow]Aviso: Erro ao extrair links: {str(e)}[/bold yellow]")
        return links

    def crawl_worker(self):
        while True:
            try:
                url, depth = url_queue.get(timeout=1)
                
                # Verificar se já visitamos esta URL
                with url_lock:
                    if url in visited_urls:
                        url_queue.task_done()
                        continue
                    visited_urls.add(url)
                
                # Fazer a requisição
                response = self.make_request(url)
                if not response or response.status_code != 200:
                    url_queue.task_done()
                    continue
                
                # Incrementar contador de páginas escaneadas
                self.pages_scanned += 1
                
                # Verificar vulnerabilidades
                self.scan_vulnerabilities(url, response)
                
                # Se ainda não atingimos a profundidade máxima, adicionar novos links à fila
                if depth < self.max_depth:
                    links = self.extract_links(response.text, url)
                    for link in links:
                        with url_lock:
                            if link not in visited_urls:
                                url_queue.put((link, depth + 1))
                
                with print_lock:
                    console.print(f"[green]Escaneado[/green]: {url} (Profundidade: {depth})")
                
            except queue.Empty:
                break
            except Exception as e:
                with print_lock:
                    console.print(f"[bold red]Erro no worker de crawling: {str(e)}[/bold red]")
            finally:
                url_queue.task_done()

    def scan_vulnerabilities(self, url, response):
        # Aqui vamos escanear por vulnerabilidades no conteúdo da resposta
        # Vamos iterar por nossa base de dados de vulnerabilidades e tentar detectá-las
        
        for vuln_id, vuln_info in VULNERABILITY_DATABASE.items():
            # Verificar se a detecção está habilitada para o tipo de URL
            if not self._should_check_vulnerability(url, vuln_info):
                continue
                
            # Tentar detectar a vulnerabilidade
            is_vulnerable, details = self._detect_vulnerability(url, response, vuln_info)
            
            if is_vulnerable:
                # Tentar explorar para confirmar
                is_confirmed = self._exploit_vulnerability(url, vuln_info, details)
                
                if is_confirmed:
                    vulnerability = {
                        "id": vuln_id,
                        "name": vuln_info["name"],
                        "url": url,
                        "severity": vuln_info["severity"],
                        "description": vuln_info["description"],
                        "details": details,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    self.vulnerabilities_found.append(vulnerability)
                    
                    with print_lock:
                        console.print(f"[bold red]VULNERABILIDADE ENCONTRADA[/bold red]: {vuln_info['name']} em {url}")
                        console.print(f"[yellow]Severidade[/yellow]: {vuln_info['severity']}")
                        console.print(f"[yellow]Descrição[/yellow]: {vuln_info['description']}")

    def _should_check_vulnerability(self, url, vuln_info):
        # Implementar lógica para determinar se uma vulnerabilidade específica
        # deve ser verificada para uma URL específica
        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path.lower()
        
        # Verificar se a vulnerabilidade só se aplica a endpoints específicos
        if "applicable_paths" in vuln_info:
            for pattern in vuln_info["applicable_paths"]:
                if pattern in path:
                    return True
            return False
        
        # Se não houver restrições específicas, verificar para todas as URLs
        return True

    def _detect_vulnerability(self, url, response, vuln_info):
        # Implementar detecção de vulnerabilidade baseada em padrões
        detection_type = vuln_info.get("detection_type", "pattern")
        
        details = {}
        is_vulnerable = False
        
        if detection_type == "pattern":
            # Verificar padrões no conteúdo da resposta
            if "response_patterns" in vuln_info:
                for pattern in vuln_info["response_patterns"]:
                    if pattern in response.text:
                        is_vulnerable = True
                        details["matched_pattern"] = pattern
                        break
        
        elif detection_type == "header":
            # Verificar cabeçalhos
            if "header_checks" in vuln_info:
                for header, expected_value in vuln_info["header_checks"].items():
                    if header in response.headers:
                        header_value = response.headers[header]
                        if expected_value in header_value:
                            is_vulnerable = True
                            details["header"] = header
                            details["value"] = header_value
                            break
        
        elif detection_type == "status_code":
            # Verificar código de status
            if "status_codes" in vuln_info:
                if response.status_code in vuln_info["status_codes"]:
                    is_vulnerable = True
                    details["status_code"] = response.status_code
        
        return is_vulnerable, details

    def _exploit_vulnerability(self, url, vuln_info, details):
        # Implementar exploração de vulnerabilidade para confirmação
        # Isso é uma simulação, em um scanner real faríamos testes mais avançados
        
        if "exploitation" not in vuln_info:
            # Se não houver método de exploração definido, confiar na detecção
            return True
        
        exploit_type = vuln_info["exploitation"].get("type")
        
        if exploit_type == "payload":
            # Enviar payload para confirmar a vulnerabilidade
            payloads = vuln_info["exploitation"].get("payloads", [])
            method = vuln_info["exploitation"].get("method", "GET")
            param = vuln_info["exploitation"].get("param", "")
            
            for payload in payloads:
                # Construir dados para o teste
                if method == "GET":
                    test_url = url + ("&" if "?" in url else "?") + param + "=" + payload
                    response = self.make_request(test_url)
                else:
                    data = {param: payload}
                    response = self.make_request(url, method=method, data=data)
                
                if response and any(pattern in response.text for pattern in vuln_info["exploitation"].get("success_patterns", [])):
                    return True
        
        elif exploit_type == "header_manipulation":
            # Manipular cabeçalhos para confirmar a vulnerabilidade
            headers = vuln_info["exploitation"].get("headers", {})
            custom_headers = HEADERS.copy()
            custom_headers.update(headers)
            
            if self.mode == "tls_client":
                response = self.client.get(url, headers=custom_headers, timeout=self.timeout)
            else:
                response = self.client.get(url, headers=custom_headers, timeout=self.timeout)
                
            if response and any(pattern in response.text for pattern in vuln_info["exploitation"].get("success_patterns", [])):
                return True
        
        # Exploração não confirmou a vulnerabilidade
        return False

    def start_scan(self):
        self.start_time = time.time()
        
        # Adicionar URL inicial à fila
        url_queue.put((self.base_url, 0))
        
        console.print(f"[bold blue]Iniciando escaneamento de [/bold blue][bold green]{self.base_url}[/bold green][bold blue] usando modo [/bold blue][bold green]{self.mode}[/bold green]")
        console.print(f"[bold blue]Profundidade máxima: [/bold blue][bold green]{self.max_depth}[/bold green][bold blue], Threads: [/bold blue][bold green]{self.num_threads}[/bold green]")
        
        # Criar e iniciar workers
        threads = []
        for _ in range(self.num_threads):
            thread = threading.Thread(target=self.crawl_worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Mostrar progresso
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[bold green]{task.fields[value]}"),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("[cyan]Escaneando...", total=None, value="")
            
            # Aguardar a conclusão de todas as URLs na fila
            while any(t.is_alive() for t in threads):
                with url_lock:
                    num_visited = len(visited_urls)
                    
                progress.update(task, value=f"{num_visited} URLs | {self.pages_scanned} páginas | {len(self.vulnerabilities_found)} vulnerabilidades")
                time.sleep(0.5)
        
        self.end_time = time.time()
        
        # Gerar relatório
        self.generate_report()
        
        # Exibir resumo
        self.display_summary()

    def generate_report(self):
        report = {
            "scan_info": {
                "target": self.base_url,
                "mode": self.mode,
                "max_depth": self.max_depth,
                "threads": self.num_threads,
                "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
                "end_time": datetime.fromtimestamp(self.end_time).isoformat(),
                "duration_seconds": self.end_time - self.start_time,
                "pages_scanned": self.pages_scanned,
                "urls_crawled": len(visited_urls)
            },
            "vulnerabilities": self.vulnerabilities_found,
            "statistics": {
                "total_vulnerabilities": len(self.vulnerabilities_found),
                "severity_counts": {
                    "critical": sum(1 for v in self.vulnerabilities_found if v["severity"] == "critical"),
                    "high": sum(1 for v in self.vulnerabilities_found if v["severity"] == "high"),
                    "medium": sum(1 for v in self.vulnerabilities_found if v["severity"] == "medium"),
                    "low": sum(1 for v in self.vulnerabilities_found if v["severity"] == "low"),
                    "info": sum(1 for v in self.vulnerabilities_found if v["severity"] == "info")
                }
            }
        }
        
        # Salvar relatório em JSON
        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
            
        console.print(f"[bold green]Relatório salvo em [/bold green][bold yellow]{self.output_file}[/bold yellow]")

    def display_summary(self):
        duration = self.end_time - self.start_time
        minutes, seconds = divmod(duration, 60)
        hours, minutes = divmod(minutes, 60)
        
        console.print("\n[bold blue]===== RESUMO DO ESCANEAMENTO =====[/bold blue]")
        console.print(f"[bold green]Alvo[/bold green]: {self.base_url}")
        console.print(f"[bold green]Duração[/bold green]: {int(hours)}h {int(minutes)}m {int(seconds)}s")
        console.print(f"[bold green]URLs visitadas[/bold green]: {len(visited_urls)}")
        console.print(f"[bold green]Páginas escaneadas[/bold green]: {self.pages_scanned}")
        console.print(f"[bold green]Vulnerabilidades encontradas[/bold green]: {len(self.vulnerabilities_found)}")
        
        # Exibir vulnerabilidades por severidade
        severity_count = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for vuln in self.vulnerabilities_found:
            severity = vuln["severity"].lower()
            if severity in severity_count:
                severity_count[severity] += 1
        
        console.print("\n[bold yellow]Vulnerabilidades por severidade:[/bold yellow]")
        console.print(f"[bold red]Crítica[/bold red]: {severity_count['critical']}")
        console.print(f"[bold #FF5500]Alta[/bold #FF5500]: {severity_count['high']}")
        console.print(f"[bold #FFAA00]Média[/bold #FFAA00]: {severity_count['medium']}")
        console.print(f"[bold #FFFF00]Baixa[/bold #FFFF00]: {severity_count['low']}")
        console.print(f"[bold #00FF00]Informativa[/bold #00FF00]: {severity_count['info']}")

def parse_arguments():
    parser = argparse.ArgumentParser(description=f"ScannerTest v{VERSION} - Scanner de Vulnerabilidades Automático")
    parser.add_argument("--url", type=str, required=True, help="URL alvo para escaneamento")
    parser.add_argument("--mode", type=str, choices=["requests", "tls_client"], default="requests", help="Modo de requisição (requests ou tls_client)")
    parser.add_argument("--depth", type=int, default=3, help="Profundidade máxima de crawling")
    parser.add_argument("--threads", type=int, default=5, help="Número de threads para escaneamento paralelo")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout para requisições em segundos")
    parser.add_argument("--output", type=str, default="report.json", help="Arquivo de saída para o relatório")
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    # Verificar se os diretórios de vulnerabilities existem
    if not os.path.exists("vulnerabilities"):
        console.print("[bold red]Erro: Diretório 'vulnerabilities' não encontrado.[/bold red]")
        console.print("[yellow]Por favor, execute este script a partir do diretório raiz do projeto.[/yellow]")
        sys.exit(1)
    
    try:
        scanner = Scanner(
            url=args.url,
            mode=args.mode,
            depth=args.depth,
            threads=args.threads,
            timeout=args.timeout,
            output=args.output
        )
        
        scanner.start_scan()
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Escaneamento interrompido pelo usuário.[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]Erro fatal: {str(e)}[/bold red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
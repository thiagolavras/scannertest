# ScannerTest

Um scanner de vulnerabilidades automático e completo desenvolvido em Python.

## Funcionalidades

- Suporte para requisições via `tls_client` ou `requests`
- Crawling automático de sites
- Base de dados extensa de vulnerabilidades conhecidas
- Verificação e exploração automática de vulnerabilidades
- Geração de relatórios detalhados

## Instalação

```bash
git clone https://github.com/thiagolavras/scannertest.git
cd scannertest
pip install -r requirements.txt
```

## Uso

```bash
python scanner.py --url https://example.com --mode requests
```

ou

```bash
python scanner.py --url https://example.com --mode tls_client
```

## Parâmetros

- `--url`: URL alvo para escaneamento (obrigatório)
- `--mode`: Modo de requisição, escolha entre `requests` ou `tls_client` (padrão: requests)
- `--depth`: Profundidade máxima de crawling (padrão: 3)
- `--threads`: Número de threads para escaneamento paralelo (padrão: 5)
- `--output`: Arquivo de saída para o relatório (padrão: report.json)
- `--timeout`: Timeout para requisições em segundos (padrão: 10)

## Exemplos

Escaneamento básico usando requests:
```bash
python scanner.py --url https://example.com
```

Escaneamento profundo usando tls_client:
```bash
python scanner.py --url https://example.com --mode tls_client --depth 5 --threads 10
```

## Avisos Legais

Este scanner deve ser usado apenas para fins educacionais e em ambientes onde você tem permissão explícita para realizar testes de segurança. O uso indevido desta ferramenta pode violar leis e termos de serviço.
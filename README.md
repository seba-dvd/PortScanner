# 🔍 SimpleScanner

**Scanner de porturi TCP scris in Python** — identifica rapid porturile deschise ale unui host folosind executie paralela prin thread-uri.

## Utilizare

```bash
python scanner.py
```

Scannerul foloseste doar biblioteci Python din standard library si trebuie utilizat exclusiv pe sisteme pentru care ai autorizatie explicita.

## Functionalitati

- Rezolvare DNS automata
- Scanare paralela a porturilor 1–1024
- Identificare servicii TCP
- Export automat al rezultatelor in fisiere `.txt`
- Intrerupere eleganta cu `Ctrl+C`

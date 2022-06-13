# Asymetrické šifrování

#### Použití
##### Šifrování
> ./seal public.pem example.pdf

##### Dešifrování
> ./open private.pem example_sealed.pdf

#### Hlavička šifrovaného souboru
Program uvažuje pouze AES128 s módem CBC.

| Pozice | Délka | Struktura | Popis |
| :------------: |:---------------:| :-----:|:-----:|
| 0 | 16 B | pole unsigned char | IV |
| 16 | 256 B | pole unsigned char | zašifrovaný klíč pomocí RSA |
| 272 | n B | ... | šifrovaná data |
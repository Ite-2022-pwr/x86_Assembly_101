# Zrozumieć asemblera tutorial

Autor: [Artur Kręgiel](https://github.com/arkregiel) <!-- aczkolwiek Chat GPT pomógł bo trochę mi się nie chce tego wszystkiego z palca pisać xd -->

## Spis treści

- [Zrozumieć asemblera tutorial](#zrozumieć-asemblera-tutorial)
  - [Spis treści](#spis-treści)
  - [Co to jest asembler?](#co-to-jest-asembler)
  - [Jakie asemblery na x86](#jakie-asemblery-na-x86)
  - [Składnie asemblera](#składnie-asemblera)
    - [1. **Kolejność operandów**](#1-kolejność-operandów)
      - [Przykład:](#przykład)
    - [2. **Prefiksy rejestrów**](#2-prefiksy-rejestrów)
      - [Przykład:](#przykład-1)
    - [3. **Sposoby adresowania**](#3-sposoby-adresowania)
      - [Przykład:](#przykład-2)
    - [4. **Stałe**](#4-stałe)
      - [Przykład:](#przykład-3)
    - [5. **Rozmiary operacji**](#5-rozmiary-operacji)
      - [Przykład:](#przykład-4)
    - [6. **Adresowanie bazowe i indeksowe**](#6-adresowanie-bazowe-i-indeksowe)
      - [Przykład:](#przykład-5)
  - [Zestaw instrukcji (ISA - Instruction Set Architecture)](#zestaw-instrukcji-isa---instruction-set-architecture)
  - [Rejestry](#rejestry)
    - [Rejestry x86](#rejestry-x86)
    - [Rejestry x86\_64](#rejestry-x86_64)
  - [Sposoby adresowania](#sposoby-adresowania)
    - [1. **Adresowanie natychmiastowe (immediate addressing)**](#1-adresowanie-natychmiastowe-immediate-addressing)
    - [2. **Adresowanie rejestrowe (register addressing)**](#2-adresowanie-rejestrowe-register-addressing)
    - [3. **Adresowanie bezpośrednie (direct addressing)**](#3-adresowanie-bezpośrednie-direct-addressing)
    - [4. **Adresowanie pośrednie (indirect addressing)**](#4-adresowanie-pośrednie-indirect-addressing)
    - [5. **Adresowanie bazowe (base addressing)**](#5-adresowanie-bazowe-base-addressing)
    - [6. **Adresowanie indeksowe (indexed addressing)**](#6-adresowanie-indeksowe-indexed-addressing)
    - [7. **Adresowanie bazowe z indeksem i przesunięciem (base-indexed with displacement addressing)**](#7-adresowanie-bazowe-z-indeksem-i-przesunięciem-base-indexed-with-displacement-addressing)
    - [8. **Adresowanie względne (relative addressing)**](#8-adresowanie-względne-relative-addressing)
    - [Przykłady kodu asemblera x86 wykorzystującego różne sposoby adresowania:](#przykłady-kodu-asemblera-x86-wykorzystującego-różne-sposoby-adresowania)
      - [Adresowanie natychmiastowe:](#adresowanie-natychmiastowe)
      - [Adresowanie rejestrowe:](#adresowanie-rejestrowe)
      - [Adresowanie bezpośrednie:](#adresowanie-bezpośrednie)
      - [Adresowanie pośrednie:](#adresowanie-pośrednie)
      - [Adresowanie bazowe:](#adresowanie-bazowe)
      - [Adresowanie indeksowe:](#adresowanie-indeksowe)
      - [Adresowanie bazowe z indeksem i przesunięciem:](#adresowanie-bazowe-z-indeksem-i-przesunięciem)
      - [Adresowanie względne:](#adresowanie-względne)
  - [Pierwszy program](#pierwszy-program)
  - [Materiały do obczajenia](#materiały-do-obczajenia)

## Co to jest asembler?

Asembler to niskopoziomowy język programowania, który bezpośrednio odpowiada instrukcjom procesora komputera. Programy napisane w asemblerze są przetwarzane przez program nazywany asemblerem (kto by się spodziewał), który tłumaczy kod asemblera na kod maszynowy - zestaw instrukcji, które procesor może wykonać bezpośrednio.

Każdy typ procesora (np. Intel x86, ARM, MIPS) ma swój własny zestaw instrukcji, który jest zrozumiały tylko dla tego konkretnego procesora. Dlatego kod asemblera napisany dla jednej architektury nie będzie działał na innej, ponieważ instrukcje i sposób adresowania różnią się między procesorami.

Na kierunku Informatyka techniczna na PWr (przynajmniej w momencie, w którym to piszę) spotkaliśmy się z dwoma różnymi asemblerami:

- x86 na przedmiotach *Organizacja i architektura komputerów* oraz *Wprowadzenie do wysokowydajnych komputerów* (czwarty semestr)
- Intel 8051 na przedmiocie *Podstawy technik mikroprocesorowych* (również czwarty semestr)

## Jakie asemblery na x86

Kilka przykładowych asemblerów na x86:

1. **NASM (Netwide Assembler)**:
   - Bardzo popularny asembler dla x86.
   - Obsługuje zarówno składnię Intel, jak i AT&T.
   - Może generować różne formaty plików obiektowych, takie jak ELF, COFF, i binarne.
   - Komenda do uruchomienia: `nasm`.

2. **MASM (Microsoft Macro Assembler)**:
   - Asembler stworzony przez Microsoft, szeroko stosowany na platformach Windows.
   - Obsługuje składnię Intel.
   - Integruje się z Visual Studio.
   - Komenda do uruchomienia: `ml`.

3. **GAS (GNU Assembler)**:
   - Część pakietu GNU Binutils.
   - Używa składni AT&T.
   - Zintegrowany z GCC i używany w środowiskach GNU/Linux.
   - Komenda do uruchomienia: `as`.

4. **FASM (Flat Assembler)**:
   - Lekki i szybki asembler.
   - Obsługuje składnię Intel.
   - Może generować różne formaty plików obiektowych i binarne.
   - Komenda do uruchomienia: `fasm`.

5. **YASM**:
   - Nowoczesny asembler inspirowany NASM.
   - Obsługuje zarówno składnię Intel, jak i AT&T.
   - Może generować różne formaty plików obiektowych.
   - Komenda do uruchomienia: `yasm`.

Ja osobiście korzystam z NASM, jednak na studiach bardziej preferowany jest GAS. Warto również wspomnieć, że pojawiające się w dalszej części tego samouczka będą pisane pod **Linuksa** i nie będą działać na Windowsie, dlatego jeśli czytelnik nie korzysta z linuksa to ~~niech zacznie~~ warto, żeby zaopatrzył się w jakąś [maszynę wirtualną](https://www.youtube.com/watch?v=nvdnQX9UkMY) bądź korzystał z [WSL-a](https://www.youtube.com/watch?v=4emmQuY25aY).

## Składnie asemblera

Składnia asemblera x86 różni się głównie w zależności od używanego asemblera i preferencji dotyczących stylu zapisu kodu. Najczęściej używane składnie to składnia Intel i składnia AT&T. Oto kluczowe różnice między nimi:

### 1. **Kolejność operandów**
- **Intel**: docelowy, źródłowy
- **AT&T**: źródłowy, docelowy

#### Przykład:

```asm
; Intel
mov eax, ebx  ; Przenosi wartość z ebx do eax

; AT&T
movl %ebx, %eax  ; Przenosi wartość z %ebx do %eax
```

### 2. **Prefiksy rejestrów**
- **Intel**: rejestry bez prefiksu
- **AT&T**: rejestry z prefiksem `%`

#### Przykład:

```asm
; Intel
mov eax, 5  ; Przenosi wartość 5 do rejestru eax

; AT&T
movl $5, %eax  ; Przenosi wartość 5 do rejestru %eax
```

### 3. **Sposoby adresowania**
- **Intel**: nawiasy kwadratowe do oznaczenia adresu pamięci
- **AT&T**: nawiasy okrągłe do oznaczenia adresu pamięci

#### Przykład:

```asm
; Intel
mov eax, [ebx]  ; Przenosi wartość z adresu wskazywanego przez ebx do eax

; AT&T
movl (%ebx), %eax  ; Przenosi wartość z adresu wskazywanego przez %ebx do %eax
```

### 4. **Stałe**
- **Intel**: stałe bez prefiksu
- **AT&T**: stałe z prefiksem `$`

#### Przykład:

```asm
; Intel
mov eax, 10  ; Przenosi wartość 10 do rejestru eax

; AT&T
movl $10, %eax  ; Przenosi wartość 10 do rejestru %eax
```

### 5. **Rozmiary operacji**
- **Intel**: rozmiar operacji jest implicit (domyślnie zależny od operandów) lub explicity za pomocą sufiksów instrukcji
- **AT&T**: rozmiar operacji jest explicity określony za pomocą sufiksów `b`, `w`, `l`, `q`

#### Przykład:

```asm
; Intel
mov al, [ebx]  ; Przenosi 8-bitową wartość z adresu wskazywanego przez ebx do al
mov eax, [ebx] ; Przenosi 32-bitową wartość z adresu wskazywanego przez ebx do eax

; AT&T
movb (%ebx), %al  ; Przenosi 8-bitową wartość z adresu wskazywanego przez %ebx do %al
movl (%ebx), %eax ; Przenosi 32-bitową wartość z adresu wskazywanego przez %ebx do %eax
```

### 6. **Adresowanie bazowe i indeksowe**
- **Intel**: `base + index*scale + displacement`
- **AT&T**: `displacement(base, index, scale)`

#### Przykład:

```asm
; Intel
mov eax, [ebx + ecx*4 + 8]  ; Przenosi wartość z adresu (ebx + ecx*4 + 8) do eax

; AT&T
movl 8(%ebx, %ecx, 4), %eax  ; Przenosi wartość z adresu (8 + %ebx + %ecx*4) do %eax
```

## Zestaw instrukcji (ISA - Instruction Set Architecture)

Każdy procesor ma swój unikalny zestaw instrukcji, które określają, jakie operacje może wykonywać. Zestaw instrukcji obejmuje operacje arytmetyczne, logiczne, kontrolne, pamięciowe i wiele innych. Zestaw instrukcji określa także format tych instrukcji, czyli jak wyglądają one w postaci binarnej.

## Rejestry

Procesory mają różne układy rejestrów, które są małymi, szybkimi pamięciami wewnętrznymi używanymi do przechowywania danych i adresów. Na przykład procesor Intel x86 ma rejestry takie jak `eax`, `ebx`, `ecx`, `edx`, podczas gdy procesor ARM ma rejestry takie jak `r0`, `r1`, `r2`.

### Rejestry x86



### Rejestry x86_64



## Sposoby adresowania

Sposoby adresowania w architekturze x86 odnoszą się do metod, jakie procesor wykorzystuje do określenia miejsca, skąd pobiera dane lub gdzie zapisuje wyniki operacji. Poniżej przedstawiam najważniejsze sposoby adresowania w architekturze x86:

### 1. **Adresowanie natychmiastowe (immediate addressing)**

Wartość operandu jest bezpośrednio określona w instrukcji.

```asm
mov eax, 5  ; przypisuje bezpośrednią wartość 5 do rejestru eax
```

### 2. **Adresowanie rejestrowe (register addressing)**

Operand znajduje się w rejestrze.

```asm
mov eax, ebx  ; przenosi wartość z rejestru ebx do rejestru eax
```

### 3. **Adresowanie bezpośrednie (direct addressing)**

Operand znajduje się w określonym adresie pamięci.

```asm
mov eax, [0x1000]  ; przenosi wartość z adresu pamięci 0x1000 do rejestru eax
```

### 4. **Adresowanie pośrednie (indirect addressing)**

Operand znajduje się w adresie pamięci wskazywanym przez rejestr.

```asm
mov eax, [ebx]  ; przenosi wartość z adresu pamięci wskazywanego przez rejestr ebx do rejestru eax
```

### 5. **Adresowanie bazowe (base addressing)**

Operand znajduje się w pamięci w adresie określonym przez rejestr bazowy plus przesunięcie.

```asm
mov eax, [ebx + 4]  ; przenosi wartość z adresu pamięci (adres w ebx + 4) do rejestru eax
```

### 6. **Adresowanie indeksowe (indexed addressing)**

Operand znajduje się w pamięci w adresie określonym przez rejestr indeksowy plus przesunięcie.

```asm
mov eax, [ebx + ecx]  ; przenosi wartość z adresu pamięci (adres w ebx + wartość w ecx) do rejestru eax
```

### 7. **Adresowanie bazowe z indeksem i przesunięciem (base-indexed with displacement addressing)**

Operand znajduje się w pamięci w adresie określonym przez rejestr bazowy, rejestr indeksowy i przesunięcie.

```asm
mov eax, [ebx + ecx + 4]  ; przenosi wartość z adresu pamięci (adres w ebx + wartość w ecx + 4) do rejestru eax
```

### 8. **Adresowanie względne (relative addressing)**

Adres jest określony jako przesunięcie względem aktualnej wartości licznika programowego (eip/rip).

```asm
jmp label  ; skok do adresu określonego etykietą 'label' (relatywny do aktualnej wartości eip)
```

### Przykłady kodu asemblera x86 wykorzystującego różne sposoby adresowania:

#### Adresowanie natychmiastowe:

```asm
mov eax, 10      ; wartość 10 jest natychmiastowa
```

#### Adresowanie rejestrowe:

```asm
mov eax, ebx     ; przenosi wartość z rejestru ebx do rejestru eax
```

#### Adresowanie bezpośrednie:

```asm
mov eax, [0x1000]  ; przenosi wartość z adresu pamięci 0x1000 do rejestru eax
```

#### Adresowanie pośrednie:

```asm
mov eax, [ebx]   ; przenosi wartość z adresu pamięci wskazywanego przez rejestr ebx do rejestru eax
```

#### Adresowanie bazowe:

```asm
mov eax, [ebx + 4]  ; przenosi wartość z adresu pamięci (adres w ebx + 4) do rejestru eax
```

#### Adresowanie indeksowe:

```asm
mov eax, [ebx + ecx]  ; przenosi wartość z adresu pamięci (adres w ebx + wartość w ecx) do rejestru eax
```

#### Adresowanie bazowe z indeksem i przesunięciem:

```asm
mov eax, [ebx + ecx + 4]  ; przenosi wartość z adresu pamięci (adres w ebx + wartość w ecx + 4) do rejestru eax
```

#### Adresowanie względne:

```asm
label:
  ; ... (kod)
  jmp label  ; skok do etykiety 'label'
```

Te sposoby adresowania pozwalają na różnorodne i elastyczne operacje na danych w programach asemblerowych, umożliwiając precyzyjne kontrolowanie przepływu danych i wykonywania programu.

Każda architektura procesora może używać różnych sposobów adresowania pamięci. Na przykład procesor x86 może używać trybu adresowania bezpośredniego, pośredniego, bazowego, z przesunięciem i wielu innych. Procesor ARM również posiada swoje specyficzne sposoby adresowania, które mogą się różnić od x86.


## Pierwszy program

## Materiały do obczajenia

- https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- https://www.nasm.us/docs.php
- https://helion.pl/ksiazki/programowanie-w-asemblerze-x64-od-nowicjusza-do-znawcy-avx-jo-van-hoey,proase.htm
- https://www.youtube.com/watch?v=jPDiaZS-2ok
- https://www.youtube.com/watch?v=VQAKkuLL31g&list=PLetF-YjXm-sCH6FrTz4AQhfH6INDQvQSn

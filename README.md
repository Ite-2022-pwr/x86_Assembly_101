# Zrozumieć asemblera tutorial

Autor: [Artur Kręgiel](https://github.com/arkregiel) <!-- aczkolwiek Chat GPT pomógł bo trochę mi się nie chce tego wszystkiego z palca pisać xd -->

Specjalne podziękowania za pomoc dla [Marcina](https://github.com/TheNNX), jesteś koxem <3

## Wstęp

Asembler wiele osób przeraża (tbh nie wiem czemu), jednak trzeba go trochę poznać, ponieważ na kierunku Informatyka techniczna na PWr (i na innych informatycznych kierunkach na innych uczelniach) ma się z nim styczność na zajęciach.

Na ITE trafisz na przedmiot *Organizacja i architektura komputerów* lub *Wprowadzenie do wysokowydajnych komputerów* (dawniej *Architektura komputerów 2*), na którym musisz pisać w asemblerze x86.

Ten tutorial niech będzie bootcampem, który pozwoli Ci - mam nadzieję - zdać laboratoria z tego przedmiotu. Jeśli chodzi o wykład to polecam książkę prof. Biernata albo prezentację z wykładów i modlitwę.

Nie zamierzam wchodzić w zbytnie szczegóły, a bardziej oswoić Cię z językiem asemblera i omówić podstawy.

Postaram się też podać [przydatne źródła informacji](#materiały-do-obczajenia) z Internetu, z których sam korzystam oraz podrzucić kilka wskazówek, ale przygotuj się, że dużą część pracy musisz wykonać samodzielnie. Google będzie Twoim przyjacielem.

Mam nadzieję, że poniższa lektura jakkolwiek ułatwi Ci otrzymanie zaliczenia.

Powodzenia <3

## Spis treści

- [Zrozumieć asemblera tutorial](#zrozumieć-asemblera-tutorial)
  - [Wstęp](#wstęp)
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
  - [Tryby adresowania](#tryby-adresowania)
    - [1. **Adresowanie natychmiastowe (immediate addressing)**](#1-adresowanie-natychmiastowe-immediate-addressing)
    - [2. **Adresowanie rejestrowe (register addressing)**](#2-adresowanie-rejestrowe-register-addressing)
    - [3. **Adresowanie bezpośrednie (direct addressing)**](#3-adresowanie-bezpośrednie-direct-addressing)
    - [4. **Adresowanie pośrednie (indirect addressing)**](#4-adresowanie-pośrednie-indirect-addressing)
    - [5. **Adresowanie bazowe (base addressing)**](#5-adresowanie-bazowe-base-addressing)
    - [6. **Adresowanie indeksowe (indexed addressing)**](#6-adresowanie-indeksowe-indexed-addressing)
    - [7. **Adresowanie bazowe z indeksem i przesunięciem (base-indexed with displacement addressing)**](#7-adresowanie-bazowe-z-indeksem-i-przesunięciem-base-indexed-with-displacement-addressing)
    - [8. **Adresowanie względne (relative addressing)**](#8-adresowanie-względne-relative-addressing)
  - [Jak właściwie wygląda program?](#jak-właściwie-wygląda-program)
  - [Pierwszy program](#pierwszy-program)
  - [Jak to uruchomić?](#jak-to-uruchomić)
    - [GNU assembly](#gnu-assembly)
    - [NASM](#nasm)
    - [makefile - przydatne](#makefile---przydatne)
    - [przedsmak inżynierii wstecznej (*reverse engineering*) - `objdump`](#przedsmak-inżynierii-wstecznej-reverse-engineering---objdump)
  - [Robienie wyrażeń warunkowych i pętli](#robienie-wyrażeń-warunkowych-i-pętli)
  - [Pisanie i wywoływanie funkcji](#pisanie-i-wywoływanie-funkcji)
  - [Ramka stosu](#ramka-stosu)
  - [Debugger (GDB)](#debugger-gdb)
  - [Łączenie C z asemblerem](#łączenie-c-z-asemblerem)
  - [Operacje zmiennoprzecinkowe na FPU](#operacje-zmiennoprzecinkowe-na-fpu)
  - [SIMD](#simd)
  - [AVX](#avx)
  - [**Przykładowe programy**](#przykładowe-programy)
    - [NWD](#nwd)
    - [Basic Input/Output](#basic-inputoutput)
  - [**Szybka nauka asemblera - cheatcode**](#szybka-nauka-asemblera---cheatcode)
  - [Materiały do obczajenia](#materiały-do-obczajenia)

## Co to jest asembler?

Asembler to niskopoziomowy język programowania, który bezpośrednio odpowiada instrukcjom procesora komputera. Programy napisane w asemblerze są przetwarzane przez program nazywany asemblerem (kto by się spodziewał), który tłumaczy kod asemblera na kod maszynowy - zestaw instrukcji, które procesor może wykonać bezpośrednio.

Każdy typ procesora (np. Intel x86, ARM, MIPS) ma swój własny zestaw instrukcji, który jest zrozumiały tylko dla tego konkretnego procesora. Dlatego kod asemblera napisany dla jednej architektury nie będzie działał na innej, ponieważ instrukcje i sposób adresowania różnią się między procesorami.

Na kierunku Informatyka techniczna na PWr (przynajmniej w momencie, w którym to piszę) spotkaliśmy się z dwoma różnymi asemblerami:

- x86 na przedmiotach [*Organizacja i architektura komputerów*](https://github.com/Ite-2022-pwr/OiAK) oraz *Wprowadzenie do wysokowydajnych komputerów* ([czwarty semestr](https://github.com/Ite-2022-pwr/ITE-IS-Semestr-4))
- Intel 8051 na przedmiocie *Podstawy technik mikroprocesorowych* (również [czwarty semestr](https://github.com/Ite-2022-pwr/ITE-IS-Semestr-4))

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

Ja osobiście korzystam z NASM, jednak na studiach bardziej preferowany jest GAS. Warto również wspomnieć, że pojawiające się w dalszej części tego samouczka będą pisane pod **Linuksa** i nie będą działać na Windowsie, dlatego jeśli czytelnik nie korzysta z Linuksa to ~~niech zacznie~~ warto, żeby zaopatrzył się w jakąś [maszynę wirtualną](https://www.youtube.com/watch?v=nvdnQX9UkMY) bądź korzystał z [WSL-a](https://www.youtube.com/watch?v=4emmQuY25aY).

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
- **Intel**: rozmiar operacji jest implicit (domyślnie zależny od operandów) lub explicity za pomocą słów kluczowych (`qword`, `dword`, `word`, `byte`)
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



## Tryby adresowania

Tryby adresowania w architekturze x86 odnoszą się do metod, jakie procesor wykorzystuje do określenia miejsca, skąd pobiera dane lub gdzie zapisuje wyniki operacji. Poniżej przedstawiam najważniejsze sposoby adresowania w architekturze x86:

### 1. **Adresowanie natychmiastowe (immediate addressing)**

Wartość operandu jest bezpośrednio określona w instrukcji.

```asm
; Intel
mov eax, 5  ; przypisuje bezpośrednią wartość 5 do rejestru eax

; AT&T
movl $5, %eax ; przypisuje bezpośrednią wartość 5 do rejestru eax
```

### 2. **Adresowanie rejestrowe (register addressing)**

Operand znajduje się w rejestrze.

```asm
; Intel
mov eax, ebx  ; przenosi wartość z rejestru ebx do rejestru eax

; AT&T
movl %ebx, %eax ; przenosi wartość z rejestru ebx do rejestru eax
```

### 3. **Adresowanie bezpośrednie (direct addressing)**

Operand znajduje się w określonym adresie pamięci.

```asm
; Intel
mov eax, [0x1000]  ; przenosi wartość z adresu pamięci 0x1000 do rejestru eax

; AT&T
movl 0x1000,%eax  ; przenosi wartość z adresu pamięci 0x1000 do rejestru eax
```

### 4. **Adresowanie pośrednie (indirect addressing)**

Operand znajduje się w adresie pamięci wskazywanym przez rejestr.

```asm
; Intel
mov eax, [ebx]  ; przenosi wartość z adresu pamięci wskazywanego przez rejestr ebx do rejestru eax

; AT&T
movl (%ebx),%eax ; przenosi wartość z adresu pamięci wskazywanego przez rejestr ebx do rejestru eax
```

### 5. **Adresowanie bazowe (base addressing)**

Operand znajduje się w pamięci w adresie określonym przez rejestr bazowy plus przesunięcie.

```asm
; Intel
mov eax, [ebx + 4]  ; przenosi wartość z adresu pamięci (adres w ebx + 4) do rejestru eax

; AT&T
movl 4(%ebx), %eax   ; przenosi wartość z adresu pamięci (adres w ebx + 4) do rejestru eax
```

### 6. **Adresowanie indeksowe (indexed addressing)**

Operand znajduje się w pamięci w adresie określonym przez rejestr indeksowy plus przesunięcie.

```asm
; Intel
mov eax, [ebx + ecx]  ; przenosi wartość z adresu pamięci (adres w ebx + wartość w ecx) do rejestru eax

; AT&T
movl (%ebx,%ecx), %eax ; przenosi wartość z adresu pamięci (adres w ebx + wartość w ecx) do rejestru eax
```

### 7. **Adresowanie bazowe z indeksem i przesunięciem (base-indexed with displacement addressing)**

Operand znajduje się w pamięci w adresie określonym przez rejestr bazowy, rejestr indeksowy i przesunięcie.

```asm
; Intel
mov eax, [ebx + ecx + 4]  ; przenosi wartość z adresu pamięci (adres w ebx + wartość w ecx + 4) do rejestru eax

; AT&T
movl 4(%ebx,%ecx), %eax    ; przenosi wartość z adresu pamięci (adres w ebx + wartość w ecx + 4) do rejestru eax
```

### 8. **Adresowanie względne (relative addressing)**

Adres jest określony jako przesunięcie względem aktualnej wartości licznika programowego (eip/rip).

```asm
jmp label  ; skok do adresu określonego etykietą 'label' (relatywny do aktualnej wartości eip)
```

Te sposoby adresowania pozwalają na różnorodne i elastyczne operacje na danych w programach asemblerowych, umożliwiając precyzyjne kontrolowanie przepływu danych i wykonywania programu.

Każda architektura procesora może używać różnych sposobów adresowania pamięci. Na przykład procesor x86 może używać trybu adresowania bezpośredniego, pośredniego, bazowego, z przesunięciem i wielu innych. Procesor ARM również posiada swoje specyficzne sposoby adresowania, które mogą się różnić od x86.

## Jak właściwie wygląda program?

![Memory layout of C programs](https://media.geeksforgeeks.org/wp-content/uploads/memoryLayoutC.jpg)

## Pierwszy program

Tradycyjnie, rozpoczynając przygodę z nowym językiem, należy napisać *Hello World!*

Jest on w kilku wersjach:

*x86 AT&T*
```asm
# hello.s
.data
  msg:
    .asciz "hello, world!\n"  # asciz - tekst ASCII zakończony 0
    msg_len = (. - msg)       # długość tekstu: bieżący adres - adres msg

.bss
.text
  .global main

main:
  mov   $4, %eax              # 4 - wywołanie write (w 32 bitowym)
  mov   $1, %ebx              # 1 - STDOUT
  mov   $msg, %ecx            # tekst 
  mov   $msg_len, %edx        # długość tekstu
  int   $0x80                 # przerwanie z numerem 0x80 - syscall

  # wyjście z programu
  # (bez tego segfault)
  mov   $1, %eax              # 1 - wywołanie exit (w 32 bitowym)
  mov   $0, %ebx              # kod zakończenia
  int   $0x80                 # syscall
```

*x86_64 AT&T*
```asm
.data 
  msg: .asciz "Hello, World!\n"
  msgLen = (. - msg)

.text

.global _start

_start:
  mov $1, %rax
  mov $1, %rdi
  mov $msg, %rsi
  mov $msgLen, %rdx
  syscall

  mov $0x3c, %rax
  mov $0, %rdi
  syscall
```

*x86 ~~normalna składnia~~ Intel (NASM)*
```asm
global _start

section .text

_start:
  mov eax, 0x4              ; use the write syscall
  mov ebx, 1                ; use stdout fd
  mov ecx, message          ; use the message as the buffer
  mov edx, message_length   ; and supply the buffer length
  int 0x80                  ; invoke the syscall

  ; exit
  mov eax, 0x1
  mov ebx, 0
  int 0x80

section .data
  message: db "Hello World!", 0xA
  message_length equ $-message ; length of the var message
```

*x86_64 Intel (NASM)*
```asm
BITS 64

section .data
    _data db "Hello, World!", 10
    
section .text
global _start

_start:
    mov rax, 1
    mov rdi, 1
    mov rsi, _data
    mov rdx, 14
    syscall
    
    mov rax, 60
    mov rdi, 0
    syscall
```

Po kolei. To jest jeszcze proste. To `BITS 64` na początku w niektórych *nasmowych* przykładach to wskazówka dla asemblera, że będziemy pisać w trybie 64-bitowym, to nieistotne. Jest to potrzebne, jeśli assembler nie ma skąd wydedukować ilości bitów (czyli na przykład z flagą `-f bin`). 

Warto też wspomnieć, że w GNU assembly komentarze rozpoczynają się od znaku `#`, a w NASM od `;`.

W sekcji `.data` mamy zaalokowany nasz napis (`db` - *define bytes* (nasm), `.asciz` - napis ASCII z NULL na końcu (gnu)) jak również w niektórych przykładach jego długość. W nasm `$` to bieżący adres czy coś takiego, więc `$-msg` oznacza *bieżąca pozycja - pozycja `msg`*, czyli po prostu **długość `msg`** - najważniejsze do zapamiętania. W GNU zamiast dolara jest `.`.

`global _start` oznacza, że ta funkcja (bo `_start` to funkcja, funkcje będą jeszcze później) będzie wyeksportowana i widoczna z zewnątrz - linker będzie ją widział oraz będzie to nasz punkt wejściowy do programu, czyli jak uruchomimy program, to wywoła się funkcja `_start`.

> O tym dlaczego w jednym przykładzie jest `main` powiem w sekcji poświęconej uruchamianiu programu, ale działa na tej samej zasadzie co `_start`.

No i tera się skup byczq

Przechodzimy do sekcji `.text`.

Systemy operacyjne mają coś takiego jak *wywołania systemowe* (syscall). Czyli taki zestaw funkcji, które coś tam robią. W tym przypadku chcemy skorzystać z wywołania systemowego czy tam funkcji systemowej `write`, która służy do wypisywania rzeczy - w naszym przypadku, bo nie tylko - na ekran.

Czyli w skrócie mówisz systemowi operacyjnemu *e, we mi to zrób pliska* i system mówi *git*.

No i tak się składa, że te wywołania systemowe mają swoje określone numery (do wygooglania *linux syscalls* albo coś w tym stylu, wierzę w cb <3). Na przykład w trybie **32-bitowym** `write` ma numer $4$, a w **64-bitowym** $1$. Nie wiem czemu tak jest, ale jest.

Wywołania systemowe oczekują *jakichś* argumentów (to się googla albo patrzy w manuala). Funkcja `write` oczekuje (w dokładnie tej kolejności):

- deskryptora pliku gdzie ma wypisać (wpisujemy 1 - STDOUT, nie zadawaj pytań)
- adresu tego czegoś co ma wypisać
- ile bajtów ma wypisać

Jak nie wierzysz to zerknij do manuala:

```
$ man 2 write
```

A tam o:

```cpp
ssize_t write(int fd, const void buf[.count], size_t count);
```

Ta, w C zamiast `printf` można użyć bezpośrednio `write`, a w asemblerze zamiast `write` można używać `printf`, ale do tego przejdziemy później, stay tuned.

```
$ man syscall
$ man syscalls
```

I teraz uwaga. W rejestrze `eax` (`rax` w 64-bitowym) umieszczamy numer naszego syscalla. Pozostałe argumenty będą przekazywane również przez rejestry, z tą różnicą, że inne rejestry są używane w trybie 32-bitowym i inne w 64-bitowym xD

_Why? Because f**k you, that's why_

(bo np. `rcx` jest sprzętowo zarezerwowany przez instrukcję `syscall`)

Ta kolejność też jest do wygooglania (jeśli nie będę aż tak leniwą paruwą czyli jak mi się zachce to wstawie jakieś linki).

W skrócie, w trybie 32-bitowym mamy:

- `ebx` - pierwszy argument (STDOUT)
- `ecx` - drugi argument (msg)
- `edx` - trzeci argument (długość msg)

A w 64-bitowym:

- `rdi` - pierwszy argument (STDOUT)
- `rsi` - drugi argument (msg)
- `rdx` - trzeci argument (długość msg)

No i jak mamy argumenty ustawione to wywołujemy funkcję systemową. W trybie 32-bitowym `int 0x80` odpowiada za wywołanie syscalla (int od `interrupt` z nr 0x80), a w 64-bitowym mamy normalnie instrukcję `syscall`.

No i nam wypisuje, jesteśmy szczęśliwi. Czy to znaczy, że można już się rozejść? NIC BARDZIEJ MYLNEGO

Jeśli byśmy na tym etapie skończyli, to by się sromotnie wydupił (segmentation fault, przyzwyczajaj się). Dlaczego? A no dlatego, że po wypiasaniu *Hello World* program by leciał po prostu dalej, mimo że już więcej instrukcji mu nie daliśmy - czyli śmieci z pamięci by traktował jak instrukcje no a tak nie wolno.

Dlatego musimy program zakończyć **poprawnie**. Na nas spoczywa ta odpowiedzialność. Jesteśmy alfą i omegą. Sigmą jak chcesz. Generalnie trzeba wywołać `exit` - czyli no mówimy systemowi operacyjnemu *dobra byq ja kończe naura*.

Robimy to podobnie jak w przypadku `write`, czyli:

| 32-bitowy | 64-bitowy
|:---:|:---:|
| do `eax` dajemy nr syscalla - $1$ | do `rax` dajemy nr syscalla - $60$ | 
| do `ebx` dajemy kod wyjścia z programu | do `rdi` dajemy kod wyjścia z programu |

Jeśli jest gituwa, nie było jakiegoś błędu po drodze to dajemy $0$. Przyjęło się, że jak program kończy z kodem $0$ to znaczy, że jego wykonanie przeszło cacy i super. Jeśli jest wartość inna niż 0, to znaczy że był jakiś błąd.

Jeśli pisałeś/pisałaś w C, to pewnie rzuciło Ci się w oczy kiedyś, że na końcu funkcji `main` jest często `return 0` - jest to właśnie z tego powodu, który opisałem powyżej.

protip: na linuksie można sprawdzić kod wyjścia ostatniego uruchomionego (w terminalu oczywiście) programu w ten sposób:

```
$ echo $?
```

Przeczytaj to wszystko sobie jeszcze raz, na spokojnie, przeanalizuj te kody (będzie Ci potrzebny tylko jeden z nich, nie wiem w jakim asemblerze zamierzasz pisać) i postaraj się zrozumieć jak najwięcej. Te hello world to podstawowa struktura programu asemblera. Dalej postaram się operować raczej na konkretnych przykładach kodów, bo nie widzę sensu tłumaczenia każdej instrukcji. Ich jest w x86 od cholery, ale będzie ci potrzebne tylko kilkanaście. Na pewno przydadzą się podstawowe operacje arytmetyczne i logiczne:

- `add` - dodawanie dwóch liczb
- `sub` - odejmuje jedną liczbę od drugiej
- `mul` i `imul` - mnożenie
- `div` i `idiv` - dzielenie oraz modulo (reszta z dzielenia)
- `and` - logiczne *and* (bitowe)
- `or` - logiczne *or* (bitowe)
- `neg` - negowanie liczby (bitów)
- `xor` - xorowanie liczb
- `cmp` - porównywanie
- `inc` - inkrementacja (+1)
- `dec` - dekrementacja (-1)
- `shr`/`sar` - przesunięcie bitowe w prawo
- `shl`/`sal` - przesunięcie bitowe w lewo

protip: zamiast robić `mov rax, 0`, można zrobić `xor rax, rax` i to da ten sam efekt - wyzeruje podany rejestr, ale jest szybsze i bardziej fancy.

Jeszcze fajna jest instrukcja `lea` (*load effective address*). Służy do obliczania adresów, ale dzięki niej można robić taką sztuczkę, że mnożymy 2 liczby, np. jeśli w `rax` mamy liczbę 3, możemy zrobić tak: `lea rax, [0+rax*4]` i wtedy będziemi w `rax` mieli liczbę 12 (a nie użyliśmy `mul`), ale to tak w ramach ciekawostki bardziej.

Generalnie ważna rzecz: jak chcesz dowiedzieć się, jak działa dana instrukcja - to to wygooglaj. Wszystko jest w internetach, także na chillku.

## Jak to uruchomić?

Mamy już kod, jesteśmy szczęśliwi - co teraz?

Teraz kod asemblera musimy przekształcić na plik *object*, a następnie zlinkować, aby dostać gotowy plik wykonywalny.

### GNU assembly

Nie będę się wdawać w szczegóły, ale musisz wykonać te dwie komendy:

- Dla 32-bitowego

```
$ as --32 -o hello.o hello.s
$ ld -m elf_i386 -o hello hello.o
```

- Dla 64-bitowego
```
$ as -o hello.o hello.s
$ ld -o hello hello.o
```

`as` (czyli asembler) wypluje nam tzw. plik *object*, czyli już plik powiedzmy binarny, ale jeszcze niezdatny do użytku.

`ld` to *linker*, który wypluje nam już gotowy plik wykonywalny, który można uruchomić.

A potem to już prościzna:

```
$ ./hello
```

Nie jestem pewien, czy w przypadku 32-bitowego nie trzeba dodawać jakichś jeszcze dodatkowych flag czy parametrów (nie korzystałem zbyt dużo z GNU assembly generalnie). Generalnie jest fajniejsza metoda asemblowania i linkowania programów, a mianowicie `gcc`.

`gcc` pewnie kojarzy ci się z kompilatorem języka C - i masz rację, ale tak naprawdę `gcc` ma w sobie kilka rzeczy:

- kompilator C, który zamienia C na asemblera (C to framework do asemblera w sumie)
- `as` - czyli nasz asembler
- `ld` - czyli nasz linker

Dodatkowo `gcc` nam od razu doda bibliotekę standardową C, jeśli jej potrzebujemy - przyda się później.

Także można to zastąpić jedną komendą:

- Dla 64-bitowego programu
```
$ gcc -o hello hello.s -no-pie
```

- Dla 32-bitowego programu

```
$ gcc -o hello hello.s -no-pie -m32
```

Warunek korzystania z `gcc` jest taki, że generalnie nasza główna funkcja musi się nazywać `main` (tak jak w C), ponieważ `gcc` sobie domyślnie dodaje swoją funkcję `_start`, w której wywołuje `main`, więc będzie oczekiwał tej nazwy.

Tłumaczenie czym jest `-no-pie` jest poza zakresem tego bootcampu, nie musisz wiedzieć co to znaczy, nie wiem nawet czy trzeba to dawać w tych przykładach, ja dodawałem na wszelki wypadek. Generalnie jeśli chcielibyśmy robić programy *na poważnie* to ze względów bezpieczeństwa **nie należy** tego robić.

### NASM

Z `nasm` jest podobnie jak w poprzednim przykładzie:

- Dla 32-bitowego

```
$ nasm -f elf32 hello.asm
$ ld -m elf_i386 -o hello hello.o
```

- Dla 64-bitowego

```
$ nasm -f elf64 hello.asm
$ ld -o hello hello.o
```

Flaga `-f` oznacza format pliku binarnego. Wykonywane pliki na linuksie są w formacie ELF. Jak wpiszesz polecenie `nasm -h` to dostaniesz listę dostępnych formatów.

Tutaj również można użyć `gcc`, ale już nie w jednej linii niestety:

```
$ nasm -f elf64 -g -F dwarf hello.asm
$ gcc -ggdb -no-pie hello.o -o hello
```

W tym przypadku `gcc` robi nam głównie za linker.

Flagi `-g` i `-F` oznaczają, że chcemy zostawić informacje do debuggowania, a `dwarf` to format debuggowania. Podobnie z flagą `-ggdb`. Na razie się tym nie przejmuj, ale to się przyda dalej.

### makefile - przydatne

Żeby nie wpisywać tego wszystkiego (zwłaszcza jak się pojawi więcej plików niż 1) można sobie stworzyć plik o nazwie *makefile*, który będzie zawierać informacje, jak to wszystko posklejać i przemielić.

- Dla GNU assembly

```
hello: hello.o
	ld -o hello hello.o
hello.o: hello.asm
	nasm -f elf64 -g -F dwarf hello.asm
```

lub

```
hello: hello.s 
	gcc -o hello hello.s -no-pie -m32
```

- Dla NASM

```
hello: hello.o
	ld -o hello hello.o
hello.o: hello.asm
	nasm -f elf64 -g -F dwarf hello.asm -l hello.lst
```

Jak chcemy użyć `gcc` to zamiast tej linijki z `ld`, dać komendę z `gcc`.

Mając gotowy plik *makefile* wystarczy wpisać:

```
$ make
```

i zrobi się samo.

To jak to działa: `make` przeczyta plik *makefile* i zobaczy regułkę `hello`, która wymaga pliku `hello.o`, więc poszuka regułki `hello.o` i zobaczy, że to wymaga pliku `hello.asm`. Plik `hello.asm` istnieje, więc wykona komendę, która wypluje `hello.o`. Następnie jak już ma plik `hello.o`, to wykona komendę, która nam da plik wykonywalny. Nie chcę się w to zbytnio zagłębiać, bo te pliki *makefile*, które będą potrzebne są krótkie i proste i można je robić *na jedno kopyto* czyli po prostu kopiować i odpowiednio pozmieniać nazwy plików.

### przedsmak inżynierii wstecznej (*reverse engineering*) - `objdump`

Wszystko jest open source, jeśli potrafi się czytać assembly. Programy można *zdeasemblować* (ang. **), czyli z postaci binarnej dostać z powrotem kod asemblera. Można to uzyskać dzięki takim narzędziom jak `objdump`:

```
$ objdump -d ./hello64

./hello64:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:       48 c7 c0 01 00 00 00    mov    $0x1,%rax
  401007:       48 c7 c7 01 00 00 00    mov    $0x1,%rdi
  40100e:       48 c7 c6 00 20 40 00    mov    $0x402000,%rsi
  401015:       48 c7 c2 0f 00 00 00    mov    $0xf,%rdx
  40101c:       0f 05                   syscall
  40101e:       48 c7 c0 3c 00 00 00    mov    $0x3c,%rax
  401025:       48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  40102c:       0f 05                   syscall
                                                    
```

Jeśli chcemy uzyskać kod w ~~normalnej~~ notacji Intela, należy dodać flagę `-Mintel`:

```
Disassembly of section .text:

0000000000401000 <_start>:
  401000:       48 c7 c0 01 00 00 00    mov    rax,0x1
  401007:       48 c7 c7 01 00 00 00    mov    rdi,0x1
  40100e:       48 c7 c6 00 20 40 00    mov    rsi,0x402000
  401015:       48 c7 c2 0f 00 00 00    mov    rdx,0xf
  40101c:       0f 05                   syscall
  40101e:       48 c7 c0 3c 00 00 00    mov    rax,0x3c
  401025:       48 c7 c7 00 00 00 00    mov    rdi,0x0
  40102c:       0f 05                   syscall
```

Liczba `0x402000` to adres, gdzie znajduje się `msg`.

Tak wygląda mój alias na komendę `objdump`:

```
$ alias objdump
objdump='objdump -d -Mintel --disassembler-color=color --visualize-jumps=extended-color'
```

## Robienie wyrażeń warunkowych i pętli

## Pisanie i wywoływanie funkcji

## Ramka stosu

## Debugger (GDB)

## Łączenie C z asemblerem

## Operacje zmiennoprzecinkowe na FPU

## SIMD

## AVX

## **Przykładowe programy**

Myślę, że najlepiej to będzie zrozumieć analizując jakieś programy - patrząc się na kod i uruchamiając pod debuggerem.

Dlatego wrzucę kilka programów, które miałem okazję napisać. 

Różne programy znajdują się też w innych repozytoriach z [OiAK](https://github.com/Ite-2022-pwr/OiAK).

### NWD

```asm
# NWD
.text
  .global _start

_start:
  push  %ebp
  mov   %esp, %ebp

  push $16          # a
  push $24          # b
  call  nwd

  mov   %ebp, %esp
  pop   %ebp

  mov   %eax, %ebx
  mov   $1, %eax    # exit
  int   $0x80

nwd:
  push  %ebp
  mov   %esp, %ebp

  while:
    movl  12(%ebp), %eax   # a
    movl  8(%ebp), %ebx   # b
    cmp   $0, %ebx
    jz    return          # if b == 0: return a

    mov   %eax, %ecx
    xor   %edx, %edx
    idiv  %ebx
    mov   %ebx, %eax      # a = b
    mov   %edx, %ebx      # b = a % b

    mov   %eax, 12(%ebp)
    mov   %ebx, 8(%ebp)
    jmp   while

  return:
  mov   %ebp, %esp
  pop   %ebp
  
  ret
```

### Basic Input/Output

```asm
BITS 64

section .data
	text1 db "What's your name? "
	text2 db "Hello, "

section .bss
	name resb  32

section .text

global _start

_start:
	call _printText1
	call _getName
	call _printText2
	call _printName

	mov rax, 60
	mov rdi, 0
	syscall

_getName:
	mov rax, 0
	mov rdi, 0
	mov rsi, name
	mov rdx, 32
	syscall
	ret

_printText1:
	mov rax, 1
	mov rdi, 1
	mov rsi, text1
	mov rdx, 18
	syscall
	ret

_printText2:
	mov rax, 1
	mov rdi, 1
	mov rsi, text2
	mov rdx, 7
	syscall
	ret

_printName:
	mov rax, 1
	mov rdi, 1
	mov rsi, name
	mov rdx, 32
	syscall
	ret
```

## **Szybka nauka asemblera - cheatcode**

`gcc` nie musi wypluwać gotowego pliku binarnego. Jeśli użyjemy flagi `-S` to wypluje nam przetłumaczony kod z C na asemblera. Co prawda będzie ona zawierał różne pierdoły, które nas niekoniecznie będą interesować podczas nauki (zwłaszcza na studia), a labele będą miały mało mówiące nazwy typu `.L69`, ale zawsze coś.

Możemy napisać prosty kod w C, a potem porównać to co napisaliśmy z wygenerowanym przez `gcc` asemblerem i zobaczyć, jak to się przekłada jedno na drugie.

Przykładowo, *Hello World* będzie wyglądać w C tak:

```cpp
#include <stdio.h>

int main()
{
    printf("Hello, World!\n");
    return 0;
}
```

A po wpisaniu `gcc -S hello.c` dostaniemy takie coś:

```asm
	.file	"hello.c"
	.text
	.section	.rodata
.LC0:
	.string	"Hello, World!"
	.text
	.globl	main
	.type	main, @function
main:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	leaq	.LC0(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
	movl	$0, %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	main, .-main
	.ident	"GCC: (Debian 12.3.0-5) 12.3.0"
	.section	.note.GNU-stack,"",@progbits
```

Osobiście zalecam też dodanie flagi `-masm=intel`, żeby dostać syntax Intela ;)

## Materiały do obczajenia

Powodzenia wariacie :3

(kolejność przypadkowa)

- [Intel® 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [Dokumentacja NASM](https://www.nasm.us/docs.php)
- [(Książka) Programowanie w asemblerze x64. Od nowicjusza do znawcy AVX](https://helion.pl/ksiazki/programowanie-w-asemblerze-x64-od-nowicjusza-do-znawcy-avx-jo-van-hoey,proase.htm#format/d)
- [you can become a GIGACHAD assembly programmer in 10 minutes (try it RIGHT NOW)](https://www.youtube.com/watch?v=6S5KRJv-7RU)
- [everything is open source if you can reverse engineer (try it RIGHT NOW!)](https://www.youtube.com/watch?v=gh2RXE9BIN8)
- [You Can Learn Assembly in 10 Minutes (it’s easy)](https://www.youtube.com/watch?v=jPDiaZS-2ok)
- [x86_64 Linux Assembly](https://www.youtube.com/playlist?list=PLetF-YjXm-sCH6FrTz4AQhfH6INDQvQSn)
- [x64 Cheat Sheet](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf)
- [x86 Assembly Guide](https://flint.cs.yale.edu/cs421/papers/x86-asm/asm.html)
- [Metody Realizacji Języków Programowania. Bardzo krótki kurs asemblera x86](https://www.mimuw.edu.pl/~ben/Zajecia/Mrj2014/Notatki/04x86.pdf)
- [Calling Conventions](https://wiki.osdev.org/Calling_Conventions)
- [(Książka, rozdział 6. Inżynieria wsteczna) Atak na sieć okiem hakera. Wykrywanie i eksploatacja luk w zabezpieczeniach sieci](https://helion.pl/ksiazki/atak-na-siec-okiem-hakera-wykrywanie-i-eksploatacja-luk-w-zabezpieczeniach-sieci-james-forshaw,ataksi.htm#format/d)

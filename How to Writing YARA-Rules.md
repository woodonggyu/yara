###### 이 글은 YARA RULE 작성 방법에 대해 설명한 글이며, 아래의 사이트를 번역하였다.
> https://yara.readthedocs.io/en/v3.4.0/writingrules.html

## **What is YARA?**
``YARA`` 는 Linux, Windows 및 MAC OS X 에서 실행되는 다중 플랫폼으로 악성코드 샘플에 포함된 패턴(Signature)을 이용하여 특성과 행위를 기준으로 악성 파일을 분류하는 오픈소스 도구이다. ``text/binary`` 패턴을 기반으로 악성코드에 대한 정책(혹은 규칙)을 만들 수 있다.  
&nbsp;
## **Writing YARA Rules**
``YARA Rule`` 은 쉽게 작성하고 이해할 수 있으며, C 언어와 유사한 구문을 사용한다. 

YARA 각각의 Rule 은 ``keyword 규칙`` 과 ``규칙 식별자(사용자 정의)`` 로 시작한다. 식별자는 ``영숫자``와 ``밑줄 문자를 포함``할 수 있지만 ``첫 번째 문자는 숫자가 될 수 없다.`` 그리고 규칙의 식별자는 ``대소문자``를 구분하여 ``128자``를 초과할 수 없으며, 아래 표의 keyword 는 예약이 되어있어 사용이 불가능하다.

| **all** | **and** | **any** | **ascii** | **at** | **condition** | **contains** |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | 
| **entrypoint** | **false** | **filesize** | **fullword** | **for** | **global** | **in** |
| **import** | **include** | **int8** | **int16** | **int32** | **int8be** | **int16be** |
| **int32be** | **matches** | **meta** | **nocase** | **not** | **or** | **of** |
| **private** | **rule** | **strings** | **them** | **true** | **uint8** | **uint16** |
| **uint32** | **uint8be** | **uint16be** | **uint32be** | **wide** | | |
&nbsp;
``Rule`` 은 일반적으로 ``strings(문자열 정의 섹션)`` 과 ``condition(조건 섹션)`` 두 섹션으로 구성된다. 
    
- Comments : YARA Rule 에 주석을 추가할 수 있다. 단일 행 및 여러 행에 대한 주석이 모두 지원된다.
    
    ```
    /*
        This is a multi-line comment ...
    */
    rule CommentExample     // ... and this is single-line comment
    {
        condition:
            false   // just an dummy rule, don't do this
    }
    ```
    &nbsp;
- strings:
    ``strings`` 는 세 가지 유형의 문자열(text string, hex string, pcre)로 작성이 가능하며, 식별자는 앞에 ``$`` 를 붙인다. 
    
    - text string : " " 사이에 ASCII 인코딩을 기준으로 작성할 수 있다.
        - Case-insensitive strings : YARA 의 텍스트 문자열은 기본적으로 ``대소문자``를 구분한다. 문자열 정의의 끝에 ``nocase`` 를 추가하여 문자열을 대/소문자 구분하지 않도록 할 수 있다.
            ```
            rule TextExample
            {
                strings:
                    $text_string = "foobar" nocase
                    
                condition:
                    $text_string
            }
            ```
            nocase 를 이용하면 foobar 문자열은 Foobar, FOOBAR, fOobar 모두 매칭된다.
        - Wide-character strings : ``wide``는 2 byte 를 하나의 글자로 읽는 인코딩에 대한 문자열을 검색할 때 사용할 수 있다. 대표적으로 Unicode가 해당된다. 단 ASCII 형태 또한 검색하고자 할 경우 ``ascii``를 추가한다.
            ```
                rule WideCharTextExample
                {
                    strings:
                        $wide_string = "UPX0" wide ascii
                    
                    condition:
                        $wide_string
                }
            ```
            아래와 같은 문자열들이 매칭된다.
            ```
             00 55 00 00 50 00 58 00 30      .U.P.X.0
            ```
        - Searching for full words : ``fullword``는 숫자나 문자가 올 경우 이를 구분하게 된다. 예를 들어 "UPX0" 라는 단어가 "aUPX0bb", "1UPX0" 등이 올 경우 이는 매칭이 되지 않는다. 하지만 "...UPX0", "UPX0_", " UPX0 " 은 매칭이 된다. 
        
            &nbsp;
    - hex string : ``hex string`` 은 ``wild-cards, jumps, alternatives``과 같은 3가지 특수 구조를 사용하여 보다 유연하게 만들 수 있다.
        - wile-card : ``{ }`` 사이에 hex 값을 입력하는데 이 때 모든 hex 값을 알지 못해도 ``wild_card('??')``를 사용하여 대체 할 수 있다. 
            ```
            rule WildcardExample
            {
                strings:
                    $hex_string = { E2 34 ?? C8 A? FB }
                    
                condition:
                    $hex_string
            }
            ``` 

        - jump : ``[ ]`` 사이에 ``하이픈으로 구분 된 한 쌍의 숫자``는 jump 이다. [X-Y] 는 0 <= X <= Y 의 조건을 만족해야 한다. YARA 의 이전 버전에서는 X, Y 값이 256 보다 작아야하지만, YARA 2.0 부터는 X 와 Y 에 제한이 없다. 패턴 매칭 속도를 향상시키기 위해서는 최소한의 범위로 줄여줄 필요가 있다.
        
            아래의 예제에서는 4~6 바이트의 임의의 시퀀스가 점프 위치를 차지할 수 있음을 나타낸다. 
            ```
            rule JumpExample
            {
                strings:
                    $hex_string = { F4 23 [4-6] 62 B4 }
                
                condition:
                    $hex_string
            }
            ```
            아래의 hex string 과 같이 매칭된다.
            ```
            F4 23 01 02 03 04 62 B4
            F4 23 00 00 00 00 00 62 B4
            F4 23 15 82 A3 04 45 22 62 B4
            ```
            
    &nbsp;
    - Regular expressions : ``정규 표현식``은 YARA 의 가장 강력한 기능 중 하나로, YARA 에서 정규 표현식을 사용하기 위해서는 ``/[정규 표현식]/`` 과 같이 두 개의 슬래시(/) 안에 정규 표현식을 사용하여야 한다. String 탐지에서 사용할 수 있었던 'nocase', 'wide', 'ascii', 'fullword' 의 기능을 사용할 수 있다.

&nbsp;
- Conditions : 조건은 모든 프로그래밍 언어에서 찾을 수 있는 것 과 같이 부울 표현식에 불과하다. 일반적인 부울 연산자(and, or, not) 및 관계연산자(>=, =, <=, ==, !=) 등을 포함할 수 있다. 또한 산술 연산자(+, -, *, /, %) 와 비트연산자(&, |, <<, >>, ~, ^)를 식에 사용할 수 있다.

    - String offsets or virtual addresses : 특정 오프셋을 통해 매칭하는 방법이다. 아래의 예제에서는 $a 는 0-100 사이의 오프셋에서 찾아야하고, $b 는 100-파일 끝 사이의 오프셋에 있어야 한다. 오프셋은 기본적으로 ``10진수``를 사용한다.
        ```
        rule InExample
        {
            strings:
                $a = "dummy1"
                $b = "dummy2"
            
            condition:
                $a in (0..100) and $b in (100..filesize)
        }
        ```
        &nbsp;
    - Count strings : 때로는 특정 문자열이 있는지 뿐만 아니라 나타나는 횟수를 알 필요가 있다. ``$`` 대신 ``#`` 으로 표시한다. 아래의 규칙은 $a 문자열을 포함하는 문자열이 6번 매칭되고, $b 문자열이 10번 초과할 경우 매칭된다.
        ```
        rule CountExample
        {
            strings:
                $a = "dummy1"
                $b = "dummy2"
            
            condition:
                #a == 6 and #b > 10
        }
        ```
        &nbsp;
    - File size : ``filesize`` 는 검사되는 파일의 크기를 포함한다. 크기는 ``byte``로 표시된다. 사용법은 아래와 같다.
        ```
        rule FileSizeExample
        {
                condition:
                    filesize > 200KB
        }
        ```
        &nbsp;
    - Executable entry point : ``entrypoint``는 파일이 ``PE(Portable Executable) 또는 ELF(Executable and Linkable Format)`` 인 경우에만 사용이 가능하다. 아래와 같이 사용가능하다.
        ```
        rule EntryPointExample1
        {
            strings:
                $a = { E8 00 00 00 00 }
            
            condition:
                $a at entrypoint
        }
        
        rule EntryPointExample2
        {
            strings:
                $a = { 9C 50 66 A1 ?? ?? ?? 00 66 A9 ?? ?? 58 0F 85 }
            
            condition:
                $a in (entrypoint..entrypoint+10)
        }
        ```
        &nbsp;
    - Accessing data at a given position : 파일이나 실행 중인 프로세스를 검사하는 경우 특정 파일 오프셋 또는 메모리 가상 주소에 저장된 데이터를 매칭하고 싶은 경우 사용한다. 상황에 따라 아래의 함수 중 하나를 사용하여 지정된 오프셋에서의 데이터를 읽을 수 있다.
    
        ``intXX`` 함수는 <offset or virtual address> 에서 8, 16, 32bit 부호있는 정수를 읽고, ``uintXX`` 함수는 부호없는 정수를 읽는다. 16, 32bit 정수는 모두 ``리틀 엔디언`` 으로 간주된다. ``빅 엔디언``을 사용하고 싶은 경우 ``be`` 사용하면 된다. 
    
        ```
        int8(<offset or virtual address>)
        int16(<offset or virtual address>)
        int32(<offset or virtual address>)
        
        uint8(<offset or virtual address>)
        uint16(<offset or virtual address>)
        uint32(<offset or virtual address>)
        
        int8be(<offset or virtual address>)
        int16be(<offset or virtual address>)
        int32be(<offset or virtual address>)
        
        uint8be(<offset or virtual address>)
        uint16be(<offset or virtual address>)
        uint32be(<offset or virtual address>)
        ```
        
        아래의 예제는 PE 파일을 구분하는 규칙하는 예제이다.
        ```
        rule IsPE
        {
            condition:
                // MZ signature at offset 0 and...
                uint16(0) == 0x5A4D and
                // ... PE signature at offset stored in MZ header at 0x3C
                uint32(uint32(0x3C)) == 0x00004550
        }
        ```
        &nbsp;
    - Sets of strings : 탐지하고자 하는 문자열이 다수일 때, 적어도 일부의 문자열이라도 탐지하고자 하는 경우에 사용된다. 사용하고자 할 경우 ``of`` 키워드를 붙여주면 된다. of 키워드 앞의 숫자는 집합 문자열 수와 같거나 작아야 한다.
        
        &nbsp;
        아래의 예제는 문자열 세트($a, $b, $c) 중 최소한 2개의 문자열이 존재할 경우 매칭된다.
        ```
        rule OfExample1
        {
            strings:
                $a = "dummy1"
                $b = "dummy2"
                $c = "dummy3"
                
            condition:
                2 of ($a, $b, $c)
        }
        ```
        &nbsp;
        집합의 요소는 아래와 같이 명시적으로 열거하거나 와일드 카드를 사용하여 지정할 수 있다.
        ```
        rule OfExample2
        {
            strings:
                $foo1 = "foo1"
                $foo2 = "foo2"
                $foo3 = "foo3"
            
            condition:
                2 of ($foo*)    /* ($foo1, $foo2, $foo3) 중 2개 이상의 문자열이 존재할 경우 매칭된다. */
        }
        
        rule OfExample3
        {
            strings:
                $a = "dummy1"
                $b = "dummy2"
                $c = "dummy3"
            
            condition:
                1 of them   /* ($*) 과 동일하게 모든 문자열에 대해 1개 이상의 문자열이 존재할 경우 매칭된다. */
        }
        ```
        &nbsp;
        문자열의 수는 상수 외에도 아래와 같이 ``all`` 또는 ``any`` 와 같은 키워드를 사용할 수도 있다.
        
        ```
        all of them       /* all strings in the rule */
        any of them       /* any string in the rule */
        all of ($a*)      /* all strings whose identifier starts by $a */
        any of ($a,$b,$c) /* any of $a, $b or $c */
        1 of ($*)         /* same that "any of them" */
        ```
        &nbsp;
    - Applying the same condition to many strings : ``for..of`` 연산자는 of 연산자와 유사하지만 더 강력하다. 구문은 다음과 같다.
        
        ```
            for [expression] of [string_set] : [boolean_expression]
        ```
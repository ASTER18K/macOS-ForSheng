# Q25(Helio G99)용 PAC 대체 계층

Zinwa Q25 Pro(MediaTek MT6789 / Helio G99, Cortex-A76 2개 + Cortex-A55 6개)에
macOS-ForSheng의 ARM64E 커널을 올리기 위한 추가분입니다.
기준은 CrossDarwin/macOS-ForSheng 커밋 `ca57db7`(macOS 26.5 / 25F71)입니다.

이 문서는 1단계(포크, Actions 빌드, QEMU에서 Recovery 화면)와
2단계(PAC가 없는 CPU 모델에서 같은 화면)만 다룹니다. 두 단계 모두 폰은 건드리지 않습니다.

## 1. 왜 필요한가

ForSheng 커널과 거기에 올리는 Apple 구성요소(corecrypto, AMFI, APFS 등), 그리고 macOS 사용자 프로그램은
전부 ARM64E로 빌드되어 포인터 인증(PAC) 명령을 씁니다.
Cortex-A76과 Cortex-A55에는 PAC가 없습니다. 이런 CPU에서는

- HINT 영역의 PAC 명령(`PACIASP`, `PACIBSP`, `AUTIASP`, `AUTIBSP` 등)은 아무 일도 하지 않는 NOP으로 실행되고,
- 나머지 PAC 명령(`RETAB`, `BLRAA`, `PACIA`, `AUTDA` 등)은 "정의되지 않은 명령" 예외를 냅니다.

그래서 PAC를 "서명해도 값이 그대로인 함수(항등 함수)"로 취급합니다.
서명과 검증이 둘 다 아무 일도 하지 않으면 프로그램 동작은 같고, 보호 기능만 없어집니다.

## 2. 구성

| 경로 | 역할 |
| --- | --- |
| `q25/tools/pac_neutralize.py` | Mach-O 안의 PAC 명령을 세거나(`scan`), 한 단어짜리 같은 동작 명령으로 바꿉니다(`rewrite`). |
| `q25/tools/neutralize_build.py` | ForSheng 커널 빌드 디렉터리 하나를 통째로 바꿔서 새 디렉터리로 냅니다. |
| `q25/tools/a64_feature_scan.py` | PAC 말고 대상 CPU가 못 돌리는 명령이 있는지 찾습니다. |
| `q25/tools/fetch_kdk.py`, `q25/tools/kdk_extract.py` | `config/macos26.json`에 고정된 Kernel Debug Kit을 받아 필요한 파일만 꺼냅니다. |
| `platform/sheng/macos26/pac/a64e/a64e.h` | PAC 명령 해석기와 실행기(커널과 시험이 같은 파일을 씁니다). |
| `platform/sheng/macos26/pac/a64e/a64e_kernel.h` | 커널의 미정의 명령 처리 쪽. |
| `platform/sheng/macos26/pac/a64e/a64e_vm.h` | 메모리에 올라온 코드 페이지의 명령을 바꾸는 쪽. |
| `platform/sheng/macos26/pac/a64e/0001-undefined-instruction-hook.patch` | 위 헤더를 XNU에 연결하는 32줄짜리 패치. |
| `patches/UniXNU/9001-darwinboot-admit-pac-neutral-arm64e.patch` | 부트로더(DarwinBoot)가 바꾼 커널만 PAC 없는 CPU에서 받도록 합니다. |
| `patches/UniXNU/9002-qemu-cpu-model-option.patch` | QEMU 실행 스크립트에 `--qemu-cpu` 옵션을 넣습니다. |
| `q25/tests/` | 자체 시험. |
| `.github/workflows/q25-tools.yml` | 자체 시험을 GitHub Actions에서 돌립니다. |

기존 파일은 세 개만 고쳤습니다.

- `scripts/build_macos26_xnu.py`: 헤더 3개를 XNU 소스에 복사하고, ARM64E 빌드의 패치 목록 끝에 위 연결 패치를 추가합니다.
- `scripts/observe_macos26_kernel.py`: `--qemu-cpu` 옵션(기본값 `cortex-a710`, 기존 동작 그대로).
- `.github/workflows/bringup.yml`: 커널 빌드 뒤에 진단용 단계 2개(바꾼 커널을 `macos26-sheng-kernel-npac`로 올림).

## 3. 동작 방식

### 3.1 커널 이미지를 미리 바꾸기

커널 코드는 예외가 나면 복구할 수 없는 곳이 많아서, 실행 전에 파일에서 전부 바꿉니다.
명령 길이가 같아서 주소가 하나도 움직이지 않고, 심볼과 dSYM도 그대로 맞습니다.

| 원래 명령 | 바꾼 명령 |
| --- | --- |
| `RETAA`, `RETAB` | `RET` |
| `ERETAA`, `ERETAB` | `ERET` |
| `BRAA`, `BRAB`, `BRAAZ`, `BRABZ` | `BR Xn` |
| `BLRAA`, `BLRAB`, `BLRAAZ`, `BLRABZ` | `BLR Xn` |
| `PACIA`, `AUTIA`, `XPACI` 등 레지스터형 | `NOP` |
| `PACGA Xd, Xn, Xm` | `AND Xd, Xn, #0xffffffff00000000` |
| `LDRAA`, `LDRAB` | `LDR`(오프셋 범위가 맞을 때만) |
| `MSR APxxKey..._EL1, Xt` | `NOP` |
| `MRS Xt, APxxKey..._EL1` | `MOV Xt, #0` |
| HINT 영역 PAC 명령 | 그대로 둠(PAC 없는 CPU에서 NOP) |

`neutralize_build.py`는 다음 경우에 결과를 내지 않고 멈춥니다.

- 한 단어로 바꿀 수 없는 명령이 남는 경우
- 코드로 표시되지 않은 실행 영역에 `RETAA`/`RETAB`가 보이는 경우(찾지 못한 코드가 있다는 뜻)
- 기록된 구성요소 수보다 찾은 구성요소가 적은 경우
- corecrypto 무결성 값(`__fips_hmacs`)이 원래 코드와 맞지 않거나 어느 코드의 값인지 정할 수 없는 경우

corecrypto는 자기 코드의 HMAC을 부팅 때 검사하므로, 코드를 바꾼 뒤 그 값을 다시 계산해 넣습니다.
`build.json`과 `security-relink.json`의 해시도 새 이미지 기준으로 고칩니다.

### 3.2 부트로더 표식

바꾼 커널의 `mach_header_64.reserved`에 `NPAC`(0x4341504E)를 써 둡니다.
패치된 DarwinBoot는 다음처럼 판단합니다.

| CPU | 표식 없는 ARM64E 커널 | 표식 있는 커널 |
| --- | --- | --- |
| PAC 있음 | 부팅(기존과 같음) | 거부 |
| PAC 없음 | 거부(기존과 같음) | 부팅 |

PAC가 있는 CPU에서 바꾼 커널을 거부하는 이유: HINT 영역 명령은 그대로 남아 있어서 실제로 서명을 하는데,
돌아갈 때 쓰는 `RETAB`는 `RET`로 바뀌어 있어 서명된 주소로 그대로 뛰게 됩니다.
QEMU 사용자 모드에서 `cortex-a710`으로 바꾼 프로그램을 돌려 실제로 죽는 것을 확인했습니다.

### 3.3 사용자 프로그램: 걸리면 고치기

사용자 프로그램과 공유 캐시는 디스크에서 바꾸지 않습니다(서명 검증이 깨지기 때문입니다).
대신 PAC 명령이 미정의 명령 예외를 내면 커널이 받아서 처리합니다.

1. 그 명령이 들어 있는 페이지가 메모리에 있고, 서명 검증을 통과했고, 아무도 쓰기로 열지 않았고, 변경된 적이 없으면
   그 한 단어만 같은 동작 명령으로 바꾸고 같은 자리에서 다시 실행합니다. 같은 자리에서는 다시 걸리지 않습니다.
2. 그렇지 않으면 저장된 레지스터 값으로 그 명령 하나를 대신 실행하고 다음 명령으로 넘어갑니다.

페이지는 "변경 없음" 상태로 둡니다. 메모리가 모자라 페이지가 버려지면 다음에 디스크에서 원본이 다시 올라오고,
다시 걸리면 다시 고칩니다. 디스크의 파일은 바뀌지 않습니다.

부트 인자 `sheng-a64e`로 조절합니다.

| 값 | 동작 |
| --- | --- |
| `0` | 끔 |
| `1` | 대신 실행만 |
| `2` | 페이지를 고치고, 안 되면 대신 실행(기본값) |

CPU에 주소 인증이 있으면(`ID_AA64ISAR1_EL1`의 APA/API가 0이 아니면) 이 코드는 아무 일도 하지 않습니다.
그래서 지금까지 검증된 `cortex-a710` 경로는 달라지지 않습니다.

커널 코드에서 PAC 명령이 걸리면(미리 바꾸는 단계에서 빠진 코드가 있다는 뜻) 대신 실행하고,
`sheng_a64e_kernel_emulated`, `sheng_a64e_kernel_last_pc`에 기록하며 처음 16번은 로그도 남깁니다.

### 3.4 QEMU CPU 선택

`observe_macos26_kernel.py --qemu-cpu <모델>`이 QEMU의 `-cpu`로 그대로 전달됩니다.

## 4. 시험 순서(사다리)

한 번에 하나만 바꿔서, 어디서 깨졌는지 알 수 있게 합니다.

| 단계 | 커널 | `--qemu-cpu` | 확인하려는 것 |
| --- | --- | --- | --- |
| L0 | 원본 | `cortex-a710` | 포크 빌드가 업스트림과 같은 결과를 내는지(1단계) |
| L1 | 바꾼 커널 | `cortex-a710,pauth=off` | PAC만 없앴을 때 커널과 사용자 프로그램이 도는지 |
| L2 | 바꾼 커널 | `cortex-a76` | A76에 없는 다른 기능(ARMv8.3 이후)에 걸리는 곳이 있는지 |
| L3 | 바꾼 커널 | `cortex-a55` | 작은 코어에서도 같은지 |

QEMU는 ForSheng이 검증한 10.2.1을 씁니다. 8.2.2는 PAC 없는 CPU 모델에서도 `RETAA`/`RETAB`를
그냥 실행하는 결함이 있어(소스에서 확인) L1 이후 단계에 쓰면 안 됩니다.

## 5. 사용 순서

### 5.1 GitHub Actions

`sheng macOS bring-up` 워크플로를 다음 값으로 실행합니다.

- `target`: `macos26-kernel`
- `native_arch`: `arm64e`
- `native_ufs`, `native_gop`, `native_input`: 켬

결과물 `macos26-sheng-kernel`이 원본 커널입니다.
이 브랜치에서 실행하면 `macos26-sheng-kernel-npac`도 함께 나옵니다. 이것은 도구가 실제 커널을
문제없이 처리하는지 보는 진단용이고, 부팅용은 아닙니다(Apple 구성요소가 아직 붙지 않은 커널입니다).

### 5.2 로컬(WSL2 등 Linux)

Apple 입력(IPSW 등) 준비, 구성요소 재배치(`scripts/emit_macos26_security.py`), 펌웨어와 로더 빌드,
QEMU 실행은 업스트림 문서(`docs/bringup.md`, `docs/debugging.md`) 순서를 그대로 따릅니다.
달라지는 것은 두 가지뿐입니다.

1. `emit_macos26_security.py`가 낸 디렉터리를 바꿉니다.

   ```sh
   python3 q25/tools/neutralize_build.py EMIT_OUTPUT_DIR NEUTRAL_DIR
   ```

   `EMIT_OUTPUT_DIR`은 emit이 만든 디렉터리, `NEUTRAL_DIR`은 아직 없는 새 디렉터리 이름입니다.

2. `observe_macos26_kernel.py`를 실행할 때 `--kernel-build`에 `NEUTRAL_DIR`을 주고
   `--qemu-cpu`를 4장의 표대로 줍니다. 나머지 인자는 L0에서 쓰던 그대로입니다.

로더는 `patches/UniXNU/9001-...`이 적용된 상태로 다시 빌드해야 합니다.
`scripts/apply_patches.py`를 실행한 뒤 `scripts/build_native_loader.sh /absolute/path/to/llvm/bin`을 실행합니다
(인자는 LLVM 실행 파일이 있는 디렉터리의 절대 경로입니다).

## 6. 자체 시험

```sh
bash q25/tests/run_all.sh
```

Apple 파일 없이 도는 시험 6묶음이 실행됩니다. Ubuntu 24.04 기준으로 필요한 패키지와 이유는 다음과 같습니다.

| 패키지 | 쓰는 곳 |
| --- | --- |
| `clang`, `lld` | 시험용 ARM64 프로그램을 만들고 커널 헤더 문법을 검사합니다. |
| `llvm` | `llvm-mc`, `llvm-objdump`로 명령 해석 결과를 대조합니다. |
| `gcc-aarch64-linux-gnu`, `libc6-dev-arm64-cross` | 예외 처리 시험 프로그램(정적 링크)을 만듭니다. |
| `qemu-user-static` | PAC 없는 CPU 모델에서 그 프로그램들을 실행합니다. |
| `7zip` | Kernel Debug Kit 디스크 이미지를 풉니다(아래 추가 시험에만 필요). |

Kernel Debug Kit을 풀어 두면 실제 Apple 커널 코드로 3묶음이 더 실행됩니다.

```sh
python3 q25/tools/fetch_kdk.py config/macos26.json private/apple
7z e -y -opkg private/apple/Kernel_Debug_Kit_26.5_build_25F71.dmg "Kernel Debug Kit/KernelDebugKit.pkg"
7z e -y -oxar pkg/KernelDebugKit.pkg KDK.pkg/Payload
python3 q25/tools/kdk_extract.py extract xar/Payload kdk \
  '^\./System/Library/Kernels/kernel\.release\.t8103$' \
  '^\./System/Library/Extensions/(corecrypto|apfs)\.kext/Contents/MacOS/(corecrypto|apfs)$'
KDK_ROOT=kdk bash q25/tests/run_all.sh
```

| 묶음 | 내용 |
| --- | --- |
| 명령 인코딩 | PAC 명령 861가지와 PAC가 아닌 명령 40가지를 LLVM 어셈블러로 만들어 해석 결과와 바꾼 명령을 대조 |
| 커널 해석기와 도구 일치 | C 해석기(`a64e.h`)와 Python 도구가 약 1,979만 단어에서 같은 답을 내는지 |
| 커널 헤더 문법 | XNU의 경고 설정(`-Weverything` 기반, 경고를 오류로)으로 헤더 3개를 가짜 선언과 함께 컴파일 |
| 무결성 값 | `__cc26_text`를 가진 커널 모양 파일에서 HMAC 재계산과 `build.json` 갱신, 거부 조건 |
| 바꾼 프로그램 실행 | 바꾼 시험 프로그램이 `cortex-a55`, `cortex-a76`, `max,pauth=off`에서 원본과 같은 결과를 내는지 |
| 걸리면 고치기 | 미정의 명령 신호를 받아 대신 실행하는 방식과 고치는 방식 둘 다 |
| (KDK) 구성요소 묶음 | 실제 corecrypto와 apfs를 ForSheng 배치로 묶어 전부 찾고 바꾸는지, HMAC이 맞는지 |
| (KDK) LLVM 대조 | `kernel.release.t8103` 전체 단어를 `llvm-objdump`와 대조 |
| (KDK) 해석기 일치 | 같은 커널의 모든 단어로 C 해석기와 도구 대조 |

## 7. 측정 결과

25F71 Kernel Debug Kit(크기와 SHA-256이 `config/macos26.json`과 일치)에서 잰 값입니다.

커널 4개와 커널 확장 733개의 PAC 명령 수:

| 종류 | 개수 |
| --- | --- |
| HINT 영역(바꿀 필요 없음) | 372,756 |
| 레지스터형 서명/검증/제거 | 742,757 |
| 인증 호출(`BLRAA` 계열) | 508,623 |
| 인증 반환(`RETAA`/`RETAB`) | 224,592 |
| 인증 분기(`BRAA` 계열) | 93,536 |
| 키 레지스터 쓰기 / 읽기 | 204 / 16 |
| `PACGA` | 118 |
| `LDRAA`/`LDRAB` | 0 |
| 한 단어로 바꿀 수 없는 것 | 0 |

바꿔야 하는 명령은 합계 1,569,846개이고 전부 한 단어로 바뀝니다.

`kernel.release.t8103`(M1용 커널) 하나를 바꾼 결과: 59,996단어 변경, 두 번째 실행에서는 0단어 변경,
남은 PAC 명령은 HINT 영역 21,882개뿐.

LLVM 역어셈블러와의 대조: 커널 2,517,005단어와 나머지 736개 파일 30,665,275단어에서 놓친 것 0, 다르게 본 것 0.

PAC 말고 Cortex-A55가 못 돌리는 명령(기준 CPU `apple-m1`):

| 범위 | 살펴본 단어 | PAC | 그 밖 |
| --- | --- | --- | --- |
| ForSheng이 올리는 확장 14개 | 979,944 | 40,321 | 272(전부 corecrypto의 SHA-3, SHA-512 명령) |
| 확장 전체 819개 파일 | 22,125,564 | 1,313,297 | 1,243(21개 파일) |

corecrypto의 SHA-3/SHA-512 명령은 소스상 실행 중에 CPU 기능을 확인하고 고르는 경로에 있습니다.
실제로 그 경로를 타지 않는지는 L2에서 확인해야 합니다.

## 8. 확인된 것과 확인되지 않은 것

확인된 것(직접 실행):

- 6장의 9묶음 시험 전부 통과.
- ForSheng 패치 78개를 적용한 XNU 소스에 연결 패치가 그대로 적용됨.
- 실제 `osfmk/arm64/sleh.c`를 clang 20으로 문법 검사했을 때 오류 0개, 추가한 헤더에서 나온 경고 0개.
  `osfmk/vm/vm_map.c`는 Apple 컴파일러에만 있는 기능 때문에 다른 곳에서 오류가 나지만, 추가한 헤더에서는 0개.
  이 검사는 빌드 중에 만들어지는 헤더 4개를 빈 파일이나 최소 선언으로 대신하고,
  커널 옵션을 `config/MASTER`에서 추정해서 한 것이라 실제 빌드를 대신하지는 못합니다.
- 워크플로의 내려받기, 풀기, 세기 단계를 같은 명령으로 로컬에서 실행.

확인되지 않은 것:

- Apple 컴파일러(Xcode 27)로 커널이 실제로 빌드되는지. Actions에서 처음 확인됩니다.
- 바꾼 커널이 부팅되는지(L1 이후 전부).
- 사용자 프로그램 쪽에서 PAC 말고 ARMv8.3 이후 명령이 얼마나 나오는지. IPSW가 있어야 셀 수 있습니다.
  나오면 `a64e.h`에 대신 실행 항목을 추가해야 합니다.
- 페이지를 고치는 방식의 속도. 명령 하나를 고칠 때마다 명령 캐시 전체를 비우므로 실기에서 느릴 수 있습니다.
- 실기(Q25)에서의 동작 전부.

## 9. 주의

- 바꾼 커널은 PAC가 있는 CPU에서 쓰면 안 됩니다. 로더가 막지만, 로더를 거치지 않는 실행 방법에서는 직접 지켜야 합니다.
- PAC가 주던 보호(반환 주소와 함수 포인터 변조 탐지)는 없어집니다. 실험용입니다.
- Apple 파일(IPSW, KDK, 거기서 꺼낸 것)은 저장소에 넣지 않습니다.


# Power Side-Channel Analysis of LUT-Based Hardware AES

A hardware security assessment of an unprotected AES-128 implementation on the **NewAE CW305 (Xilinx Artix-7) FPGA**, using **Correlation Power Analysis (CPA)** and **Test Vector Leakage Assessment (TVLA)**.

## Overview

This project evaluates whether a round-per-cycle, LUT-based AES-128 hardware core leaks information through its power consumption.

Power traces were captured using the ChipWhisperer framework and analyzed using two complementary methods:

- **Correlation Power Analysis (CPA):** A non-profiled attack using a last-round Hamming-distance leakage model.
- **Test Vector Leakage Assessment (TVLA):** First- and second-order Welch's t-tests to detect statistically significant leakage independently of a key hypothesis.

The assessment found exploitable leakage in the captured implementation. CPA recovered the final-round key and reversed the AES-128 key schedule to recover the original 128-bit test key. TVLA independently detected substantial first- and second-order leakage.

## Target Platform

| Parameter | Details |
|---|---|
| Target Board | NewAE CW305 |
| FPGA | Xilinx Artix-7 |
| Encryption Algorithm | AES-128 |
| Architecture | LUT-based, round-per-cycle |
| Capture Framework | ChipWhisperer |
| Number of Traces | 2,000 |
| Samples per Trace | 80 |
| Plaintext | Random plaintexts |
| Encryption Key | Fixed FIPS-197 test key |
| Attack Target | Final-round state-register transition |

### Experimental AES Key

`2B7E151628AED2A6ABF7158809CF4F3C`

This is a publicly known FIPS-197 reference test key used for experimental validation.

## Methodology

### 1. Power Trace Capture

The ChipWhisperer capture setup synchronizes the ADC to the FPGA clock using `extclk_x4`.

The experiment uses:
- FPGA PLL1 output frequency: 10 MHz
- ADC trigger mode: Rising edge
- Trigger pin: TIO4
- Target supply voltage: 1.0 V
- Number of captured traces: 2,000

For each capture, a random plaintext is generated, AES encryption is triggered, and the power waveform and ciphertext are recorded.

The DUT ciphertext is verified against an independent software AES-ECB reference implementation.

### 2. Correlation Power Analysis (CPA)

The attack targets the Hamming distance between the AES state before and after the final-round transition.

Since the final AES round does not contain MixColumns, each output byte can be attacked independently for each of the 16 last-round key bytes.

The attack:
1. Generates candidate key-byte hypotheses.
2. Computes hypothetical Hamming-distance leakage.
3. Calculates Pearson correlation between predicted leakage and measured power traces.
4. Identifies the most likely last-round key byte.
5. Reverses the AES-128 key schedule to recover the original encryption key.

### 3. Test Vector Leakage Assessment (TVLA)

TVLA uses Welch's t-test to identify statistically significant power leakage.

The conventional leakage detection threshold is:

`|t| > 4.5`

Two statistical orders were evaluated:

- **First-Order TVLA:** Applied directly to raw power samples.
- **Second-Order TVLA:** Applied to mean-centered, squared power samples.

TVLA provides an independent statistical assessment without requiring a specific key hypothesis.

## Experimental Results

| Metric | Result |
|---|---:|
| Number of Captured Traces | 2,000 |
| CPA Maximum Correlation | ≈ 0.235 |
| CPA Peak Sample | ≈ 57 |
| Recovered Key Verification | Successful |
| First-Order TVLA Maximum | 64.15 |
| First-Order Leaking Samples | 52 / 80 (65%) |
| Second-Order TVLA Maximum | 28.95 |
| Second-Order Leaking Samples | 47 / 80 (59%) |
| TVLA Threshold | 4.5 |

### CPA Results

The CPA leakage profile shows a prominent correlation peak around sample 57, reaching approximately 0.235.

This indicates a strong, time-localized, key-dependent leakage event corresponding to the final-round state transition.

The recovered last-round key was reversed through the AES-128 key schedule, successfully matching the original test key.

### First-Order TVLA Results

- Maximum absolute t-statistic: 64.15
- Leaking samples: 52 out of 80
- Percentage of leaking samples: 65%
- Detection threshold: |t| > 4.5

The results demonstrate substantial first-order power leakage.

### Second-Order TVLA Results

- Maximum absolute t-statistic: 28.95
- Leaking samples: 47 out of 80
- Percentage of leaking samples: 59%
- Detection threshold: |t| > 4.5

The results demonstrate that statistically significant leakage is also present in higher-order power measurements.

## Repository Structure

The report identifies the following code and dataset artifacts:

```text
.
├── README.md
├── capture_hw_aes.ipynb
├── cpa_attack.ipynb
├── tvla_analysis.py
├── aes_core_lut.v
├── aes_sbox_lut.v
└── AES_HW_CW305_Full_Dataset_LUT.xlsx
```

**Note:** The report explicitly identifies `aes_core_lut.v` and `aes_sbox_lut.v` as placeholders. Actual RTL source files must be added before claiming that the complete hardware implementation is available.

## Software Requirements

The experimental environment uses:

- Python 3.9
- ChipWhisperer
- ChipWhisperer Analyzer
- NumPy
- SciPy
- PyCryptodome
- Bokeh
- tqdm
- Jupyter Notebook

Install the supporting Python dependencies:

```bash
python -m pip install numpy scipy pycryptodome bokeh tqdm jupyter
```

ChipWhisperer should be installed separately using its official documentation:

https://chipwhisperer.readthedocs.io/

## Reproducing the Experiment

1. Connect the CW305 target board and a compatible ChipWhisperer capture device.
2. Open `capture_hw_aes.ipynb`.
3. Configure the target, ADC, PLL and trigger settings.
4. Capture the power traces and save the resulting dataset.
5. Open `cpa_attack.ipynb` to perform the CPA attack.
6. Execute `tvla_analysis.py` to calculate first- and second-order Welch's t-statistics.
7. Generate the leakage plots and compare the results with the experimental findings.

Exact file paths, project filenames and data-loading configurations may need adjustment depending on the repository contents.

## Limitations

- The assessment uses a fixed, publicly known FIPS-197 test key.
- The dataset contains 2,000 traces with 80 samples each.
- The analysis focuses on the final AES-round transition.
- Leakage from earlier AES rounds was not separately characterized.
- No measurement-noise sensitivity analysis was performed.
- No electromagnetic side-channel assessment was conducted.
- The RTL files listed in the report are placeholders.

## Future Work

Potential extensions include:

- Implementing masked AES hardware to evaluate resistance against first- and second-order leakage.
- Exploring hiding-based countermeasures.
- Evaluating template attacks and deep-learning-based side-channel analysis.
- Performing electromagnetic side-channel measurements.
- Conducting trace-count sensitivity analysis to determine the minimum number of traces required for reliable key recovery.

## References

1. NewAE Technology Inc., [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/).
2. NewAE Technology Inc., [NAE0010: CW305 AES Side-Channel Attack Whitepaper](http://media.newae.com/appnotes/NAE0010_Whitepaper_CW305_AES_SCA_Attack.pdf).
3. NewAE Technology Inc., [Tutorial CW305-1: Building a Project](http://wiki.newae.com/Tutorial_CW305-1_Building_a_Project).
4. NIST, [FIPS 197: Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final).
5. E. Brier, C. Clavier and F. Olivier, "Correlation Power Analysis with a Leakage Model," CHES 2004.
6. G. Goodwill, B. Jun, J. Jaffe and P. Rohatgi, "A Testing Methodology for Side-Channel Resistance Validation," NIST Non-Invasive Attack Testing Workshop, 2011.
7. P. Kocher, J. Jaffe and B. Jun, "Differential Power Analysis," CRYPTO 1999.

---

**Project Scope:** This repository documents an authorized laboratory evaluation of side-channel leakage in an FPGA-based AES implementation. The results apply to the tested hardware, capture configuration and dataset and should not be generalized to all AES implementations or FPGA devices.

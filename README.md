# from pathlib import Path

readme = r'''# Power Side-Channel Analysis of LUT-Based Hardware AES

A hardware security assessment of an unprotected AES-128 implementation on the **NewAE CW305 (Xilinx Artix-7) FPGA**, using **Correlation Power Analysis (CPA)** and **Test Vector Leakage Assessment (TVLA)**.

## Overview

This project evaluates whether a round-per-cycle, LUT-based AES-128 hardware core leaks information through its power consumption. Power traces were captured with the ChipWhisperer framework and analyzed using two complementary methods:

- **Correlation Power Analysis (CPA):** a non-profiled attack using a last-round Hamming-distance leakage model.
- **Test Vector Leakage Assessment (TVLA):** first- and second-order Welch's t-tests to detect statistically significant leakage independently of a key hypothesis.

The assessment found exploitable leakage in the captured implementation. CPA recovered the final-round key and reversed the AES-128 key schedule to recover the original 128-bit test key. TVLA independently detected substantial first- and second-order leakage.

## Target and experiment

| Item | Details |
|---|---|
| Target board | NewAE CW305 |
| FPGA | Xilinx Artix-7 |
| Cipher | AES-128 |
| Architecture | LUT-based, one AES round per clock cycle |
| Capture framework | ChipWhisperer |
| Dataset | 2,000 power traces |
| Samples per trace | 80 (CW-Husky capture configuration described in the report) |
| Plaintexts | Random plaintexts |
| Key | Fixed FIPS-197 test key |
| Main analysis point | Final-round state-register transition |

The fixed test key used for the experiment was:

```text
2B7E151628AED2A6ABF7158809CF4F3C
```

This is a published AES test key used for experimental validation, not a production secret.

## Methodology

### 1. Power-trace capture

The ChipWhisperer capture setup synchronizes the ADC to the FPGA clock using `extclk_x4`. The report describes a 10 MHz PLL1 output, a rising-edge trigger on `tio4`, and a target core voltage of 1.0 V.

For each capture, the experiment generates a plaintext, triggers AES encryption, records the power waveform and ciphertext, and checks the DUT ciphertext against an independent AES-ECB software reference.

### 2. Correlation Power Analysis (CPA)

The attack targets the Hamming distance between the AES state before and after the final-round transition. Since the final AES round omits MixColumns, each output byte can be attacked independently for each of the 16 last-round key bytes.

The analysis evaluates candidate key-byte hypotheses and correlates predicted Hamming-distance leakage with measured power samples. The recovered last-round key is then rolled back through the AES-128 key schedule to obtain the original key.

### 3. Test Vector Leakage Assessment (TVLA)

Welch's t-test is applied sample-by-sample to compare trace populations. The report uses the conventional decision threshold:

```text
|t| > 4.5
```

- **First-order TVLA:** applied to raw power samples.
- **Second-order TVLA:** applied to mean-centered, squared power samples.

TVLA does not require guessing the AES key; it provides a statistical test for data-dependent leakage.

## Results

| Metric | Result |
|---|---:|
| Number of traces | 2,000 |
| CPA maximum absolute correlation | Approximately 0.235 at sample 57 |
| Recovered key verification | Matched the known test key |
| First-order TVLA maximum \|t\| | 64.15 |
| First-order leaking samples | 52 / 80 (65%) |
| Second-order TVLA maximum \|t\| | 28.95 |
| Second-order leaking samples | 47 / 80 (59%) |
| TVLA threshold | \|t\| > 4.5 |

### Interpretation

- The CPA correlation peak around sample 57 indicates a time-localized, key-dependent leakage event around the final-round state transition.
- First-order TVLA substantially exceeds the 4.5 threshold, with 52 of 80 samples flagged.
- Second-order TVLA also exceeds the threshold, with 47 of 80 samples flagged.
- Together, the results show that the assessed unprotected implementation is vulnerable to power side-channel analysis under the experimental conditions.

## Repository contents

The report identifies the following code and data artifacts. Add the corresponding files to the repository when publishing the complete experiment:

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

**Important:** In the report, `aes_core_lut.v` and `aes_sbox_lut.v` are explicitly described as placeholders. Replace them with the actual RTL sources before presenting them as a working implementation. The README does not imply that these files, the notebooks, or the dataset are already present in the repository.

## Software and tools

The report lists the following software stack:

- Python 3.9
- ChipWhisperer (`chipwhisperer`)
- ChipWhisperer Analyzer (`chipwhisperer.analyzer`)
- NumPy
- SciPy
- PyCryptodome (`Crypto.Cipher.AES`)
- Bokeh
- tqdm
- Jupyter Notebook

Install the Python dependencies in an environment compatible with the ChipWhisperer hardware setup. A typical starting command is:

```bash
python -m pip install numpy scipy pycryptodome bokeh tqdm jupyter
```

Install ChipWhisperer using the official installation instructions for your operating system and hardware. The capture notebook requires a compatible ChipWhisperer capture device and a connected CW305 target; the analysis can be adapted to run on previously saved traces.

## Reproducing the analysis

1. Connect and configure the CW305 target and a compatible ChipWhisperer capture device.
2. Open `capture_hw_aes.ipynb` and configure the target, scope, clock, and trigger.
3. Capture the traces and save the resulting ChipWhisperer project or exported dataset.
4. Open `cpa_attack.ipynb` and run the last-round CPA and AES key-schedule reversal.
5. Run `tvla_analysis.py` on the captured trace groups to calculate first- and second-order Welch's t-statistics.
6. Compare the generated leakage plots and numerical results with the results summarized above.

Exact paths, project filenames, and data-loading code depend on the files included in the repository and may need to be configured before running.

## Limitations

- The assessment uses a fixed, publicly known FIPS-197 test key.
- The reported dataset contains 2,000 traces of 80 samples each, focused on the final-round transition.
- Earlier AES rounds were not separately characterized in this report.
- The report does not include a measurement-noise sensitivity sweep or an EM side-channel assessment.
- The report describes non-specific fixed-vs-random TVLA; other TVLA configurations could provide complementary evidence.
- The RTL source files listed in the report are placeholders and must not be treated as complete source code.

## Future work

Potential extensions identified in the report include:

- Evaluate masked and hiding-based AES implementations against both first- and second-order leakage.
- Explore profiled attacks, including template attacks and deep-learning-based side-channel analysis.
- Perform electromagnetic side-channel measurements.
- Sweep the number of traces to estimate the minimum trace count needed for reliable key recovery.

## References

1. NewAE Technology Inc., [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/).
2. NewAE Technology Inc., [NAE0010: CW305 AES Side-Channel Attack Whitepaper](http://media.newae.com/appnotes/NAE0010_Whitepaper_CW305_AES_SCA_Attack.pdf).
3. NewAE Technology Inc., [Tutorial CW305-1: Building a Project](http://wiki.newae.com/Tutorial_CW305-1_Building_a_Project).
4. NIST, [FIPS 197: Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final).
5. E. Brier, C. Clavier, and F. Olivier, “Correlation Power Analysis with a Leakage Model,” CHES 2004.
6. G. Goodwill, B. Jun, J. Jaffe, and P. Rohatgi, “A Testing Methodology for Side-Channel Resistance Validation,” NIST Non-Invasive Attack Testing Workshop, 2011.
7. P. Kocher, J. Jaffe, and B. Jun, “Differential Power Analysis,” CRYPTO 1999.

---

**Project scope:** This repository documents an authorized laboratory evaluation of side-channel leakage in an FPGA AES implementation. Results apply to the tested hardware, capture setup, and dataset; they should not be generalized to all AES implementations or FPGA devices.
'''
path = Path("/mnt/data/README.md")
path.write_text(readme, encoding="utf-8")
print(f"Created {path} ({path.stat().st_size} bytes)")

NEXORA VULNSCAN TEST SAMPLES

These are intentionally weak, harmless text samples to demonstrate Nexora's static rules.
They are not real credentials or deployed infrastructure. Do not deploy the Dockerfile or Terraform sample.

HOW TO TRY EACH MODULE
1. Open Nexora and make sure your API key is saved in Settings.
2. Choose New Assessment and select a module.
3. Code & Dependencies: paste sample_source.py. Separately paste requirements.txt to try dependency lookup.
4. Container Security: paste Dockerfile.
5. Cloud & IaC: paste main.tf.
6. Confirm you are authorized to assess the sample, then run the check.

Checks are heuristic and may not flag every pattern. OSV results can change.

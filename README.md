mythica_run - Start a background Houdini job
===

```bash
usage: mythica_run.py [-h] --input-file INPUT_FILE [INPUT_FILE ...]
                      [--output-path OUTPUT_PATH]
                      [--job-per-input JOB_PER_INPUT] --endpoint ENDPOINT
                      --key KEY [--job-def JOB_DEF]
mythica_run.py: error: the following arguments are required: --input-file/-i, --endpoint/-e, --key/-k

# e.g.

./mythica_run.py --output-path /tmp/mythica --input-path ./*.fbx -k XXX
```

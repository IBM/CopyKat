# Taint verification for CCOs

This repo contains the code necessary to verify the data flows for candidate CCOs. The starting point is a set of syzkaller reports and reproducers and the kernel against which they were obtained.

## Dependencies

- docker-ce: 24.0.2
- docker-compose-plugin: 2.18.1
- python: 3.10.12
- gcc: 11.4.0

## Instructions

At first we extract metadata about the crash from the logs

```
./01.extract-info.py --crashes ./repros/ --outfile db/01.data
```

The output is collected in `db/01.data`. We then proceed to compile all reproducers:

```
./02.compile.py --reports-file db/01.data --path repros/ --outdir ./repros/
```

At this point we bring up the container and log into it

```
cd panda/
docker compose up -d
docker exec -it panda-syz-rrr-1 bash
```

First of all we need to execute all reproducers under panda:

```
./kdo/run-repros.py --reports-file db/01.data --path /root/repro/ --outfile db/record.1.json
```

This will create a panda trace file that can later be replayed by the various analyses. The command will take a considerable amount of time to first of all boot the QEMU snapshot and then sequentially record executions. The program generates a recording file called `db/record.1.json`. Recordings might fail: grepping the string `"err"` will reveal recording errors. This does not reflect any fundamental issues with the approach: recording errors occur because our termination detection and timeout logic are not sufficiently sophisticated to capture all cases. We have witnessed that it was sufficient to retry and have created the following script to do so. As long as there are still errors in the output file, you can run

```
./kdo/rerun-repros.py --reports-file db/01.data --record-file db/record.1.json --path /root/repro/ --outfile db/record.2.json
```

making sure to specify the outfile of the previous attempt (be it `run-repros.py` or `rerun-repros.py` depending on whether it's the first attempt or not) as `--record-file` and a new filename for the new `--outfile`. So for example you would go

```
./kdo/run-repros.py --reports-file db/01.data --path /root/repro/ --outfile db/record.1.json
./kdo/rerun-repros.py --reports-file db/01.data --record-file db/record.1.json --path /root/repro/ --outfile db/record.2.json
./kdo/rerun-repros.py --reports-file db/01.data --record-file db/record.2.json --path /root/repro/ --outfile db/record.3.json
./kdo/rerun-repros.py --reports-file db/01.data --record-file db/record.3.json --path /root/repro/ --outfile db/record.4.json
```

to attempt 4 recordings. After this step is done, we can gather recording data back into the DB by running:

```
./03.mergeRecordResults.py --infile db/01.data --outfile db/02.data --recordfile db/record.2.json
```

making sure to use the latest file specified in `--outfile` as `--recordfile`. This will update the DB with information about the recordings.

Now the analysis step can start. Analyses take time since PANDA will re-emulate all instructions in the recording and interrupt execution when callbacks from the analysis request it. Our analysis scripts run either for all candidates (default) or for a specific candidate by supplying the `--repro-id` argument. We recommend starting from a single repro.

### Single reproducer analysis

Assuming you want to analyse reproducer `1a4d23ffdbc209e3336c8b3c93371c63c01663d2`, you run:

```
./kdo/analysis1/run-analysis.py --record-file db/record.2.json --repro-id 1a4d23ffdbc209e3336c8b3c93371c63c01663d2
```

```
./04.mergeReplayResults.pass1.py --infile db/02.data --outfile db/03.data --path panda/out/
```

```
./kdo/analysis2/run-analysis.py --record-file db/03.data --repro-id 1a4d23ffdbc209e3336c8b3c93371c63c01663d2
```

```
./05.mergeReplayResults.pass2.py --infile db/03.data --outfile db/04.data --path panda/out/
```

```
./kdo/analysis3/run-analysis.py --record-file db/04.data --repro-id 1a4d23ffdbc209e3336c8b3c93371c63c01663d2
```

```
./06.mergeReplayResults.pass3.py --infile db/04.data --outfile db/05.data --path panda/out/
```

This will collect all information for the selected reproducer and make it available in `db/05.data`. At this point, the DB can be used for the S2E analysis.

### Bulk replay

Bulk replay can be obtained by simply omitting the `--repro-id` argument. That will spin up as many PANDA instances running the analysis in parallel as the machine has cores. Note that high degree of parallelism will also imply high memory consumption. We have tested on a machine with 40 cores and 46 gigs of ram and have not run out of memory. The degree of parallelism can be controlled with `--npar`.

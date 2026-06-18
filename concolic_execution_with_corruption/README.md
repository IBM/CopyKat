# S2E Installation

## Before starting
### Machine Requirements
At least 32GB of RAM
We need at least 1 Core :-)
At least 150GB of Disk space.

### Setup
Our scripts are set to run CopyKat on a medium sized machine (20 cores and 32 GB of RAM).
Based on your machine specs, you can edit under `s2e-data/scripts/run_\*.sh` and set how many parallel jobs -i.e., `Pool(20)`-your machine can support .
We advise to set `N_CORES-1`. However if you are heavily memory constrained (e.g., <16) do not exceed 10 jobs.

Furthermore, given that some cases take quite long, to get as many results as possible in the shortest time, we placed a timeout of 1h to prevent these longer cases to take over all the workers in your system and stall the progress.

## Installing
### Generate docker container with CopyKat S2E

```bash
docker build -t s2e-image .
```

### Create permanent container from CopyKat s2e-image

```bash
docker run -dit --name s2e --restart unless-stopped s2e-image
```

### Connect to image

```bash
docker exec -it s2e bash
```
## Execute Analysis
Now, if no errors were encountered, you are ready to run the analysis.

We provide two scripts. The first only runs the analysis on our successfully verified reproducers, as from the tables in the paper. (Recommended)

The second one runs all the 222 cases from the Panda analysis. This considerably increases the time of execution especially on small machines. (Not recommended)

### Run paper results experiments (inside the container)
This command only runs on the 122 verified objects from the paper.
The script can be interrupted and would restart from the remaining objects to be verified.

```bash
python $DATA/scripts/run_successful_ids.py

```

### Run all cases (inside the container)
```bash
python $DATA/scripts/run_all.py
```

### Run case manually (inside the container)
It is also possible to run each individual test by hand. For instance, if we want to re-run our running example from the paper:

```bash
cd 408bf2a23593a83e9ab66cc2982c30d87e52b223
./launch.sh
```
Once it is completed, it is also possible to inspect manually the output which can be accessed by looking at the files in `s2e-last`.

`debug.txt` provides the output of our plugin

`serial.txt` provides information from within the guest machine

`counterfeit-memcpy.txt` provides constraints collected at memcpy

`counterfeit-return.txt` provides constraints collected at return (if not panic)

`report.txt` provides general information (e.g., number of constraints, signal) about our test, generated if the analysis does not fail (e.g., s2e crashes)

## Verification of progress and results
### Check progress (inside the container)
To check the progress, it is possible, from another shell connected to the container through `docker exec`, to run one of the following commands.
In essence, they look for valid `report.txt` where signal is true.

```bash
find -name report.txt  | xargs -I {} grep -l true {}
find -name report.txt  | xargs -I {} grep -l true {} | wc -l
```

### Create DB and queries to explore the results (inside the container)
The following commands can be run while the analysis is running as they only look for valid `report.txt`
By running the following command:

```bash 
python $DATA/scripts/process_result.py
```
it is possible to create a sqlite db from the results with aggregated data.

By running:

```bash
bash $DATA/scripts/query_table_final.sh
```
it is possible to obtain the data in the format as they are in our paper. It will, of course, only include the objects that your setup successfully verified.

## Known problems

### Timeout triggering for some objects
Around ~100 objects run quite fast (~5 Minutes each), and are reproducible consistently.
The remaining ones take considerably longer as they might require multiple runs to observe the primitive.
Furthermore, their execution time requires more than 1 hour and our script currently has a timeout of 1 hour.

Few reproducers require some manual tweak from the default configuration of S2E to work.
Specifically, they require `bootstrap.sh` to be changed and each line starting with `sysctl` should be commented out.
Given the small amount of cases involved, we did not automate this step.
It is possible to inspect, for the cases that might not provide a signal, our archive with constraints under Zenodo, to verify which settings/configs were used exactly and if manual tweaks were made.

### Docker image creation
Sometimes when creating the container the linking of one of the components fails with this error.
This is a spurious docker issue unrelated to our system.

``` bash
/usr/bin/ld: cannot find -lglibc-compat-main: No such file or directory
clang-14: error: linker command failed with exit code 1 (use -v to see invocation)
```

Normally, re-running a second time the `docker build -t s2e-image .` solves it.

If this is not solved, please comment out the last command in the Dockerfile.
After, terminate the generation of the s2e-image without the `s2e build` command.
Then, run and connect to the image.
Running `s2e build` from within the container should always work without issues.


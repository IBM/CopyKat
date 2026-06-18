from multiprocessing import Pool
import os
import fileinput
from pathlib import Path
from subprocess import DEVNULL, STDOUT, Popen, TimeoutExpired

projects = []

def mbr_run(folder):
    print ("Handling {}".format(folder))
    try:
        first = True
        found = False
        while (True):
            my_env = os.environ.copy()

            if (Path(folder+"/s2e-last/report.txt").is_file()):
                with open(folder + "/s2e-last/report.txt", "r") as report:
                    for line in report:
                        if "signal: true" in line:
                            found = True

            if found:
                break

            # Turn switch in case report does not exist or contain signal and it is not the first iteration
            # for line in fileinput.input(folder+"/s2e-config.lua", inplace=True):
                # if (not first):
                    # if "kdo_fork_state" in line:
                        # line = line.replace("false", "true")

                # print(line, end='')
                # else:
                    # if "kdo_fork_state" in line:
                        # line.replace("false", "true")

            process = Popen(["./launch-s2e.sh", "--name {}".format(folder)],
                stdout=DEVNULL, shell=True,
                stderr=STDOUT,
                cwd=folder, env=my_env)
            first = False
            process.wait(timeout=3600)

    except TimeoutExpired:
        print ("Experiment {} timed out".format(folder))
        for child_process in process.children(recursive=True):
            child_process.kill()
        process.kill()
        process.wait()
        print ("Process killed {}".format(folder))
        return

    print ("Finished {}".format(folder))
    return


if __name__ == '__main__':
    with Pool(20) as p:
        with open("/home/s2e/data/scripts/successful_ids.txt") as mylist:
            line = mylist.readline()
            while line:
                projects.append(os.getcwd()+"/"+line.strip())
                line = mylist.readline()
        # for d in os.listdir(os.getcwd()):
           # if (os.path.isdir(d)):
               # projects.append(os.getcwd()+"/"+d)
        p.map(mbr_run, projects)
    print("Finished running all jobs\n")


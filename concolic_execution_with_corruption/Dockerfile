FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
        git \
        curl \
        wget \
        ca-certificates \
        sudo \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        gcc \
        g++ \
        vim \
        htop \
        clang \
        make \
        cmake \
        ninja-build \
        pkg-config \
        autoconf \
        automake \
        libtool \
        sqlite3 \
        texinfo && \
    rm -rf /var/lib/apt/lists/*

# Create user
RUN useradd -m -s /bin/bash s2e && \
    echo "s2e ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/s2e && \
    chmod 0440 /etc/sudoers.d/s2e

# Copy local files (includes data/patches)
COPY s2e-data /home/s2e/data

# Clone repo, checkout commit, then apply patch
RUN git clone https://github.com/S2E/s2e-env.git /home/s2e/s2e-env && \
    cd /home/s2e/s2e-env && \
    git checkout 6b10450bb && \
    git apply /home/s2e/data/patches/s2e-env.patch

# Create venv AFTER patch
RUN python3 -m venv /home/s2e/s2e-env/venv && \
    . /home/s2e/s2e-env/venv/bin/activate && \
    chown -R s2e:s2e /home/s2e/s2e-env/venv


# Auto-activate on login shells
RUN echo "source /home/s2e/s2e-env/venv/bin/activate" >> /home/s2e/.bashrc
RUN echo "source /home/s2e/cco_s2e/s2e_activate" >> /home/s2e/.bashrc
RUN echo "cd /home/s2e/cco_s2e/projects" >> /home/s2e/.bashrc

ENV PATH="/home/s2e/venv/bin:$PATH"

RUN cd /home/s2e/s2e-env && pip3 install .

USER s2e
WORKDIR /home/s2e

# Initialize a clean s2e installation
RUN s2e init cco_s2e

# Set all the projects to the right point and patch with CCO changes
RUN cd /home/s2e/cco_s2e/source/s2e && \ 
    git checkout 3063162e19d85dab969e2f9d98cc2916b9a888f4 && \
    git apply /home/s2e/data/patches/cco_s2e.patch && \
    cd /home/s2e/cco_s2e/source/guest-images && \
    git checkout a7989a2e97303cb2d6a1e399969b3517256e7209 && \ 
    git apply /home/s2e/data/patches/guest-images.patch && \
    cd /home/s2e/cco_s2e/source/scripts && \
    git checkout cfc158d7b82b55e21982e04cf9109f09cb3ed614 && \
    cd /home/s2e/cco_s2e/source/qemu && \
    git checkout 6a865ba1b1c9f5e32cd2cd9dc12ed5972addd567 

# Copy plugin into our fresh s2e install
RUN  cp -r /home/s2e/data/s2e-plugin/cco /home/s2e/cco_s2e/source/s2e/libs2eplugins/src/s2e/Plugins/ 

# Create folder and copy CCO pre-snapshotted image with instrumented kernel
RUN mkdir /home/s2e/cco_s2e/images/buildroot-6.4.1 && cp -rp /home/s2e/data/s2e-image/* /home/s2e/cco_s2e/images/buildroot-6.4.1/

# Fix timestamp to load snapshot
RUN touch -d @1777381128 /home/s2e/cco_s2e/images/buildroot-6.4.1/rootfs.ext4
RUN touch -d @1777381128 /home/s2e/cco_s2e/images/buildroot-6.4.1/rootfs.ext4.ready

# Generate projects from CCO database
RUN cd /home/s2e/data/database && TERM=xterm-256color S2EDIR=/home/s2e/cco_s2e DATA=/home/s2e/data python3 scripts/dbtos2e.py panda.data ubts.processed.data

# Update config files
RUN cd /home/s2e/data/reproducers/configs/ && ls | cut -d"." -f 1 | xargs -I {} cp {}.lua /home/s2e/cco_s2e/projects/{}/s2e-config.lua

# Fix ownership
RUN sudo chown -R s2e:s2e /home/s2e/data/scripts
RUN sudo chown -R s2e:s2e /home/s2e/data/database/scripts

# Environment variables
ENV CCOHOME=/home/s2e
ENV DATA=/home/s2e/data

# Compile s2e
RUN . /home/s2e/s2e-env/venv/bin/activate && . /home/s2e/cco_s2e/s2e_activate && s2e build


CMD ["/bin/bash"]

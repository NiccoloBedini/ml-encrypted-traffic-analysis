# Use a Debian base image
FROM debian:bullseye-slim

# Set the non interactive environment for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Update the system and install the required dependencies
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    curl \
    subversion \
    python3-pip 

# Install Selenium
RUN pip3 install selenium

# Install pandas
RUN pip3 install pandas
RUN pip3 install scikit-learn

# Install tshark
RUN apt-get install -y tshark

# Copy the python script inside the container
COPY browser_simulations.py /app/browser_simulations.py

# Set the work directory
WORKDIR /app

#### Install tstat
RUN apt-get update \
    && apt-get install -y autoconf automake libtool \
       libpcap0.8-dev \
       libcap2 \
    && svn checkout http://tstat.polito.it/svn/software/tstat/trunk tstat \
    && cd tstat \
    && ./autogen.sh \
    && ./configure --enable-libtstat --enable-zlib \
    && make \
    && make install 

# Install Firefox
RUN apt-get update && apt install -y firefox-esr \
    && wget https://github.com/mozilla/geckodriver/releases/download/v0.33.0/geckodriver-v0.33.0-linux64.tar.gz \
    && tar -xvf geckodriver-v0.33.0-linux64.tar.gz \
    && rm geckodriver-v0.33.0-linux64.tar.gz \
    && mv geckodriver /usr/local/bin

## Install Chrome
RUN apt-get update \
   && wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
   && apt-get install -y ./google-chrome-stable_current_amd64.deb \
   && apt-get install -f \
   && wget https://edgedl.me.gvt1.com/edgedl/chrome/chrome-for-testing/120.0.6099.71/linux64/chromedriver-linux64.zip \
   && unzip chromedriver-linux64.zip \
   && mv chromedriver-linux64/chromedriver /usr/local/bin \
   && rm -r c*

### Install Edge
RUN apt-get update \
    && curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg \
    && install -o root -g root -m 644 microsoft.gpg /etc/apt/trusted.gpg.d/ \
    && sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/edge stable main" > /etc/apt/sources.list.d/microsoft-edge-dev.list' \
    && rm microsoft.gpg \
    && apt update \
    && apt-get install -y microsoft-edge-dev \
    && wget https://msedgedriver.azureedge.net/121.0.2277.4/edgedriver_linux64.zip \
    && unzip edgedriver_linux64.zip \
    && mv msedgedriver /usr/local/bin \
    && rm edgedriver_linux64.zip  \
    && rm google*

# docker build -t image .
# docker run -it --privileged --name image container
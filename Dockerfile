FROM ruby:3
RUN apt update -qqy && apt upgrade -qqy && apt clean && rm -r /var/lib/apt/lists/*
RUN mkdir -p /opt/scanner
ENV LANG=C.UTF-8 \
    BUNDLE_JOBS=4 \
    BUNDLE_APP_CONFIG=/opt/scanner/.bundle

COPY Gemfile Gemfile.lock /opt/scanner

WORKDIR /opt/scanner
RUN bundle config --local path .cache/bundle
RUN --mount=type=cache,target=/opt/scanner/.cache/bundle \
    bundle install && \
    mkdir -p vendor && \
    cp -ar .cache/bundle vendor/bundle
RUN bundle config --local path vendor/bundle

COPY run.rb /opt/scanner
COPY funcs.rb /opt/scanner

RUN apt-get update -qqy && apt-get install -qqy wget apt-transport-https gnupg lsb-release && \
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && \
    echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install trivy && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

CMD ["ruby", "/opt/scanner/run.rb"]

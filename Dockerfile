FROM ruby:latest
RUN mkdir -p /opt/scaner
COPY Gemfile Gemfile.lock /opt/scaner

WORKDIR /opt/scaner

RUN bundle config set app_config .bundle
RUN bundle config set path .cache/bundle
RUN --mount=type=cache,target=/opt/scaner/.cache/bundle \
    bundle install && \
    mkdir -p vendor && \
    cp -ar .cache/bundle vendor/bundle
RUN bundle config set path vendor/bundle

COPY run.rb /opt/scaner

CMD ["ruby", "/opt/scaner/run.rb"]

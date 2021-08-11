FROM ruby:2.7
RUN mkdir -p /opt/scaner
COPY Gemfile Gemfile.lock /opt/scaner

WORKDIR /opt/scaner
ENV BUNDLE_APP_CONFIG ".bundle"
RUN bundle config --local set path .cache/bundle
RUN --mount=type=cache,target=/opt/scaner/.cache/bundle \
    bundle install && \
    mkdir -p vendor && \
    cp -ar .cache/bundle vendor/bundle
RUN bundle config --local set path vendor/

COPY run.rb /opt/scaner

CMD ["ruby", "/opt/scaner/run.rb"]

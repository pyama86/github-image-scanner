FROM ruby:2.7
RUN mkdir -p /opt/scaner
ENV LANG=C.UTF-8 \
    BUNDLE_JOBS=4 \
    BUNDLE_APP_CONFIG=/opt/scaner/.bundle

COPY Gemfile Gemfile.lock /opt/scaner

WORKDIR /opt/scaner
RUN bundle config --local path .cache/bundle
RUN --mount=type=cache,target=/opt/scaner/.cache/bundle \
    bundle install && \
    mkdir -p vendor && \
    cp -ar .cache/bundle vendor/bundle
RUN bundle config --local path vendor/bundle

COPY run.rb /opt/scaner

CMD ["ruby", "/opt/scaner/run.rb"]

FROM ruby:2.7
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

CMD ["ruby", "/opt/scanner/run.rb"]

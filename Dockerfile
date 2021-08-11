FROM ruby:latest
RUN apt update -qqy && apt install -qqy sudo
#RUN useradd -m -u 1000 scaner
#RUN mkdir -p /opt/scaner && chown -R scaner /opt/scaner
#COPY --chown=scaner Gemfile Gemfile.lock /opt/scaner
#
#USER scaner
#WORKDIR /opt/scaner
#
#RUN bundle config set app_config .bundle
#RUN bundle config set path .cache/bundle
#RUN --mount=type=cache,uid=1000,target=/opt/scaner/.cache/bundle \
#    bundle install && \
#    mkdir -p vendor && \
#    cp -ar .cache/bundle vendor/bundle
#RUN bundle config set path vendor/bundle
#
#COPY --chown=scaner run.rb /opt/scaner
#
#CMD ["ruby", "/opt/scaner/run.rb"]

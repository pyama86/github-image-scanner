require 'graphql/client'
require 'graphql/client/http'
require 'docker'
require 'octokit'
require 'yaml'
require 'logger'
require 'date'

logger = Logger.new($stdout)
config = YAML.load_file('./config.yml')
Octokit.configure do |c|
  c.api_endpoint = ENV['GITHUB_API']
end

module SWAPI
  HTTP = GraphQL::Client::HTTP.new(File.join(ENV['GITHUB_API'].gsub(%r{v3/?}, ''), 'graphql')) do
    def headers(_context)
      h = {
        "User-Agent": 'github-image-scanner'
      }
      h['Authorization'] = "token #{ENV['GITHUB_TOKEN']}" if ENV['GITHUB_TOKEN']
      h
    end
  end

  Schema = GraphQL::Client.load_schema(HTTP)
  Client = GraphQL::Client.new(schema: Schema, execute: HTTP)
end

trivy = Docker::Image.create('fromImage' => 'aquasec/trivy')
if config['registory_domain']
  Docker.authenticate!('username' => ENV['GITHUB_USER'], 'password' => ENV['GITHUB_TOKEN'],
                       'serveraddress' => "https://#{config['registory_domain']}")
end

client = Octokit::Client.new(
  access_token: ENV['GITHUB_TOKEN'],
  auto_paginate: true,
  per_page: 300
)

created = []
config['orgs'].each do |o|
  Object.send(:remove_const, :Query) if Object.constants.include?(:Query)

  type = begin
    client.organization(o)
    'organization'
  rescue StandardError
    'user'
  end

  Query = SWAPI::Client.parse <<~GRAPHQL
    {
      #{type}(login: "#{o}") {
        packages(packageType: DOCKER, first: 100) {
          edges {
            node {
              name
              id
              repository {
                name
              }
              versions(first: 1, orderBy: {field: CREATED_AT, direction: DESC}) {
                nodes {
                  id
                  version
                }
              }
            }
          }
        }
      }
    }
  GRAPHQL

  response = SWAPI::Client.query(Query)
  if data = response.data
    data.to_h[type]['packages']['edges'].each do |i|
      result = {}
      r = i['node']['repository']['name']
      next if i['node']['versions']['nodes'].empty?

      begin
        imn = i['node']['name']
        v = i['node']['versions']['nodes'].first['version']
        image_name = "#{config['registory_domain']}/#{o}/#{r}/#{imn}:#{v}"

        logger.info "check image name #{image_name}"

        next if config['ignore_images'].find { |i| image_name =~ /#{i}/ }

        image = Docker::Image.create('fromImage' => image_name)
        vols = []
        vols << "#{ENV['CACHE_DIR'] || "#{Dir.pwd}/cache"}:/tmp/"
        vols << '/var/run/docker.sock:/var/run/docker.sock'
        container = ::Docker::Container.create({
                                                 'Image' => trivy.id,
                                                 'HostConfig' => {
                                                   'Binds' => vols
                                                 },
                                                 'Cmd' => [
                                                   '--cache-dir',
                                                   '/tmp/',
                                                   '--ignore-unfixed',
                                                   '--light',
                                                   '-s',
                                                   'HIGH,CRITICAL',
                                                   '--format',
                                                   'template',
                                                   '--template',
                                                   '@contrib/html.tpl',
                                                   '--exit-code',
                                                   '1',
                                                   image_name
                                                 ]
                                               })

        container.tap(&:start).attach do |stream, chunk|
          result[stream] ||= []
          result[stream] << chunk
        end

        result[:status_code] = container.wait['StatusCode']
        container.remove(force: true)
        logger.info "check result #{o}/#{r} exit:#{result[:status_code]}"

        next if result.empty? || (result[:status_code]).zero?

        err = []
        issue_txt = "# These images have vulnerabilites.\n"
        issue_txt << result[:stdout].compact.join("\n")
                                    .gsub(%r{<head>.+?</head>}m, '')
                                    .gsub(%r{</?body>}m, '')
                                    .gsub(%r{</?html>}m, '')
                                    .gsub(/^\d{4}-\d{2}-\d{2}T\d{2}.+$/, '')
                                    .gsub(/<!DOCTYPE html>/, '')
                                    .gsub(/^\s*$/, '')
                                    .gsub(/^\n/, '')
                                    .gsub(/^    /m, '')

        raise err.compact.join("\n") if result[:stderr]&.size&.positive?

        logger.info issue_txt
        logger.info result.inspect
        raise "sume error happend: #{result.inspect}" if issue_txt == 'These images have vulnerabilites.'

        logger.info "create issue #{o}/#{r}"
        issue = client.create_issue("#{o}/#{r}", "#{Date.today.strftime('%Y/%m/%d')} Found vulnerabilities in #{image_name}", issue_txt)
        created << "- [ ] [#{image_name}](#{issue.url})"
      rescue StandardError => e
        logger.error "#{o}/#{r} happend error #{e}"
      end
    end
  elsif response.errors.any?
    if response.errors.messages['data'].first =~ /API rate limit exceeded for user ID/
      sleep 60
      redo
    end
    logger.error response.errors.messages['data']
  end
end

if created.size.positive? && config['report_repo'] 
  client.create_issue(config['report_repo'], "#{Date.today.strftime('%Y/%m/%d')} container scan report",
                      "These containers has vulunabilities\n#{created.join("\n")}")
end

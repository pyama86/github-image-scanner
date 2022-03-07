require 'graphql/client'
require 'graphql/client/http'
require 'octokit'
require './funcs'
require 'logger'
require 'date'

def normalize_issue_url(url)
  url.gsub(/api\/v3\/repos\//, '')
end

logger = Logger.new($stdout)
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

client = Octokit::Client.new(
  access_token: ENV['GITHUB_TOKEN'],
  auto_paginate: true,
  per_page: 300
)

cve_summary = {}
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
      r = i['node']['repository']['name']
      next if i['node']['versions']['nodes'].empty?

      begin
        imn = i['node']['name']
        v = i['node']['versions']['nodes'].first['version']
        image_name = "#{config['registory_domain']}/#{o}/#{r}/#{imn}:#{v}"
        logger.info "check image name #{image_name}"
        next if config['ignore_images'].find { |i| image_name =~ /#{i}/ }

        result = scan_image(image_name, image_remove: true)
        next if result.empty? || result['Results'].none? {|r| r.key?("Vulnerabilities") }

        ignore_vulnerabilities = ignore_vulnerabilities_for(config, image_name)

        issue_txt, cve_summary = scan_result_to_issue_md(result, cve_summary, ignore_vulnerabilities)
        if issue_txt
          logger.info "create issue #{o}/#{r}"
          issue = client.create_issue("#{o}/#{r}", "#{Date.today.strftime('%Y/%m/%d')} Found vulnerabilities in #{image_name}", issue_txt.slice(0, 65500))
          created << "- [ ] [#{image_name}](#{normalize_issue_url(issue.url)})"
        end
      rescue StandardError => e
        logger.error "#{o}/#{r} happend error #{e}"
        logger.error e.backtrace.join("\n")
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
  issue_txt = "These containers has vulunabilities\n#{created.join("\n")}\n\n"
  issue_txt << cve_summary_md(cve_summary)
  client.create_issue(config['report_repo'], "#{Date.today.strftime('%Y/%m/%d')} container scan report", issue_txt.slice(0, 65500))
end

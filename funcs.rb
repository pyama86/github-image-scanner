require 'docker'
require 'yaml'
require 'markdown-tables'
require 'fileutils'
def config
  @_config ||= YAML.load_file('./config.yml')
end

def which(cmd)
  exts = ENV['PATHEXT'] ? ENV['PATHEXT'].split(';') : ['']
  ENV['PATH'].split(File::PATH_SEPARATOR).each do |path|
    exts.each do |ext|
      exe = File.join(path, "#{cmd}#{ext}")
      return exe if File.executable?(exe) && !File.directory?(exe)
    end
  end
  nil
end

def scan_image(image_name, image_remove: false)
  cache_path = ENV['VOLUME_PATH'] ? "#{ENV['VOLUME_PATH']}/cache" : "#{Dir.pwd}/cache"
  out_path = ENV['VOLUME_PATH'] ? "#{ENV['VOLUME_PATH']}/out" : "#{Dir.pwd}/out"
  ignore_path = ENV['VOLUME_PATH'] ? "#{ENV['VOLUME_PATH']}/.trivyignore" : "#{Dir.pwd}/.trivyignore"

  FileUtils.mkdir_p(out_path)

  image = Docker::Image.create('fromImage' => image_name)
  ignore_cves = image.json.dig('Config', 'Labels', 'ignore_cves')&.split(/,\s?/)
  ignore_cves += config['ignore_cves'] || []
  File.open(ignore_path, mode = 'w') { |f| f.write(ignore_cves.join("\n")) }

  result = {}
  cmd = [
    '--cache-dir',
    './cache',
    'image',
    '--ignore-unfixed',
    '--no-progress',
    '-s',
    'HIGH,CRITICAL',
    '--format',
    'json',
    '--exit-code',
    '1',
    '--ignorefile',
    './.trivyignore',
    '--output',
    './out/result.json',
    image_name
  ]

  File.delete(File.join(out_path, 'result.json')) if File.exist?(File.join(out_path, 'result.json'))
  if which('trivy')
    system("trivy #{cmd.join(' ')}")
  else
    @trivy ||= Docker::Image.create('fromImage' => 'aquasec/trivy:latest')
    if config['registory_domain']
      @_auth ||= {}
      @_auth[config['registory_domain']] || Docker.authenticate!('username' => ENV['GITHUB_USER'], 'password' => ENV['GITHUB_TOKEN'],
                                                                 'serveraddress' => "https://#{config['registory_domain']}")
    end

    cmd.each_with_index do |_, i|
      cmd[i].gsub!(%r{\./}, '/opt/')
    end

    vols = []
    vols << "#{cache_path}:/opt/cache/"
    vols << "#{out_path}:/opt/out/"
    vols << "#{ignore_path}:/opt/.trivyignore"
    vols << '/var/run/docker.sock:/var/run/docker.sock'

    container = ::Docker::Container.create({
                                             'Image' => @trivy.id,
                                             'WorkDir' => '/opt',
                                             'HostConfig' => {
                                               'Binds' => vols
                                             },
                                             'Cmd' => cmd
                                           })
    container.start
    container.streaming_logs(stdout: true, stderr: true) { |_, chunk| puts chunk.chomp }

    container.wait(120)
    container.remove(force: true)
  end
  image.remove(force: true) if image_remove
  JSON.parse(File.read(File.join(out_path, 'result.json')))
end

# Trivy Scan Result JSON to Markdown Report
# @param result [Hash] Trivy Scan Result JSON
# @param cve_summary [Hash]
# @param ignore_vulnerabilities [Array]
# @return [Array]
def scan_result_to_issue_md(result, cve_summay = {}, ignore_vulnerabilities = [])
  return [nil, cve_summay] if result.empty? || result['Results'].none? { |r| r.key?('Vulnerabilities') }

  issue_txt = "# These images have vulnerabilites.\n"
  labels = %w[target type name path installed fixed cve]
  data = []
  result['Results'].each do |r|
    next unless r['Vulnerabilities']

    vulnerabilites = r['Vulnerabilities'].map do |v|
      next if ignore_vulnerabilities.include? v['VulnerabilityID']

      cve_summay[v['VulnerabilityID']] ||= {}

      cve_summay[v['VulnerabilityID']]['Type'] = r['Type']
      cve_summay[v['VulnerabilityID']]['PkgName'] = v['PkgName']

      cve_summay[v['VulnerabilityID']]['PrimaryURL'] = v['PrimaryURL']

      cve_summay[v['VulnerabilityID']]['Artifacts'] ||= []
      unless cve_summay[v['VulnerabilityID']]['Artifacts'].include?(result['ArtifactName'])
        cve_summay[v['VulnerabilityID']]['Artifacts'].push(result['ArtifactName'])
      end

      [
        r['Class'] == 'os-pkgs' ? 'os' : r['Target'],
        r['Type'],
        v['PkgName'],
        v.fetch('PkgPath', '-'),
        v['InstalledVersion'],
        v['FixedVersion'],
        "[#{v['VulnerabilityID']}](#{v['PrimaryURL']})"
      ]
    end

    data.concat(vulnerabilites.compact)
  end

  issue_txt << MarkdownTables.make_table(labels, data, is_rows: true)
  [issue_txt, cve_summay]
end

# @param cve_summary [Hash]
# @return [String]
def cve_summary_md(cve_summary)
  labels = ['cve', 'name', 'affected images']

  data = cve_summary.map do |k, v|
    [
      "[#{k}](#{v['PrimaryURL']})",
      v['PkgName'],
      v['Artifacts'].join('<br>')
    ]
  end

  MarkdownTables.make_table(labels, data, is_rows: true)
end

# @param config [Hash]
# @param image_name [String]
# @return [Array]
def ignore_vulnerabilities_for(config, image_name)
  return [] unless config.key? 'ignores'

  vulnerabilites = config['ignores'].map do |ignore|
    image_name.match?(ignore['image']) ? ignore['vulnerabilities'] : []
  end

  vulnerabilites.flatten
end

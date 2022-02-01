# frozen_string_literal: true

require 'rake/testtask'

Rake::TestTask.new(:test) do |t|
  t.test_files = FileList['tests/test_*.rb']
  t.ruby_opts = []
  t.verbose = false
  t.warning = false
end

task default: :test

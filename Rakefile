directory 'build'

task :run_cmake => 'build' do
   Dir.chdir('build') do
      sh 'cmake .. && make && src/mytest'
   end
end

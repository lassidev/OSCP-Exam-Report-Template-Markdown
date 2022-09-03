#!/usr/bin/env ruby

templates = [
  {
    exam: 'OSCP',
    name: 'Testing report',
    path: 'src/testreport.md'
  },
  {
    exam: 'OSCP',
    name: 'Final report',
    path: 'src/finalreport.md'
  }
]

# Choose template
puts '[+] Choose a template:'
templates.each_with_index do |t,i|
  puts "#{i}. [#{t[:exam]}] #{t[:name]}"
end
print '> '
choice = gets.chomp
src = templates[choice.to_i][:path]
exam = templates[choice.to_i][:exam]

# Enter your OS id
puts "\n[+] Enter your OS id"
print '> OS-'
osid = 'OS-' + gets.chomp

# Choose syntax highlight style
style = 'breezedark'
puts "\n[+] Choose syntax highlight style [#{style}]"
print '> '
choice = gets.chomp
style = choice unless choice.empty?
puts style

# Generating report
puts "\n[+] Generating report..."
pdf = "output/#{exam}-#{osid}-Exam-Report.pdf"
%x(pandoc #{src} -o #{pdf} \
  --from markdown+yaml_metadata_block+raw_html \
  --template eisvogel \
  --table-of-contents \
  --toc-depth 6 \
  --number-sections \
  --top-level-division=chapter \
  --highlight-style #{style} \
  --resource-path=.:src \
  -V colorlinks=true \
  -V linkcolor=teal \
  -V urlcolor=teal 

)
puts "\n[+] PDF generated at #{pdf}"

# Preview
puts "\n[+] Do you want to preview the report? [y/N]"
print '> '
choice = gets.chomp
if choice.downcase == 'y'
  viewer = fork do
    exec "xdg-open #{pdf}"
  end
  Process.detach(viewer)
end

# Generating archive
#puts "\n[+] Generating archive..."
#archive = "output/#{exam}-#{osid}-Exam-Report.7z"
#%x(7z a #{archive} \
  #{File.expand_path(pdf)}
#)

# Optional lab report
#puts "\n[+] Do you want to add an external lab report? [y/N]"
#print '> '
#choice = gets.chomp
#if choice.downcase == 'y'
#  puts "\n[+] Write the path of your lab PDF"
#  print '> '
#  lab = gets.chomp
#  puts "\n[+] Updating archive..."
#  %x(7z a #{archive} \
    #{File.expand_path(lab)}
#  )
#end

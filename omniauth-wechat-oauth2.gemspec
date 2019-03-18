version = File.read(File.expand_path('../VERSION', __FILE__)).strip

Gem::Specification.new do |s|
  s.platform    = Gem::Platform::RUBY
  s.name        = 'omniauth-wechat-oauth2'
  s.version     = version
  s.summary     = 'Omniauth strategy for wechat(weixin)'
  s.description = 'Using OAuth2 to authenticate wechat user when web resources being viewed within wechat(weixin) client.'

  s.files        = Dir['README.md', 'lib/**/*']
  s.require_path = 'lib'
  s.requirements << 'none'
  s.required_ruby_version     = '>= 2.0.0'

  s.author       = ['Skinnyworm', 'Never Min']
  s.email        = ['askinnyworm@gmail.com', 'Never.Min@gmail.com']
  s.homepage     = 'https://github.com/nevermin/omniauth-wechat-oauth2'
  s.license      = 'MIT'

  s.add_dependency 'omniauth', '~> 1.3.2'
  s.add_dependency 'omniauth-oauth2', '>= 1.1.1'
  s.add_development_dependency 'rspec', '~> 2.7'
end

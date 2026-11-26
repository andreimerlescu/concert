# Rack & Rails Integration

## Rack (`config.ru`, Sinatra, Hanami, Roda)

Attach `ConcertClient::Priority::RackMiddleware` to emit a validated `Concert-Priority` response header on matching requests:

```ruby
require "concert_client"

use ConcertClient::Priority::RackMiddleware, default_ttl: 1800 do |env|
  path = env["PATH_INFO"].to_s
  if path.start_with?("/admin")
    ["staff", 28_800]
  elsif path.start_with?("/checkout")
    "checkout"
  end
end

run MyRackApp
```

Returning `nil` leaves the response without a `Concert-Priority` header. Concert strips `Concert-Priority` before responses reach browsers and stores the signed grant in the `concert_priority` cookie.

## Ruby on Rails (Railtie + Controller Concern)

When loaded inside a Rails application, `ConcertClient::Priority::Railtie` automatically:

1. Includes `ConcertClient::Priority::ControllerConcern` in `ActionController`.
2. Installs `RackMiddleware` if `config.concert_priority.resolver` is configured.

### Option A: Controller Helpers

```ruby
class ApplicationController < ActionController::Base
  after_action :attach_concert_priority

  private

  def attach_concert_priority
    sync_concert_priority(
      staff: current_user&.staff?,
      subscriber: current_user&.active_subscription?,
      customer: current_user&.orders&.exists?,
      member: current_user.present?
    )
  end
end

class SessionsController < ApplicationController
  def destroy
    clear_concert_priority # emits "Concert-Priority: guest" to clear the grant
    reset_session
    redirect_to root_path
  end
end
```

### Option B: Application Middleware (`config/application.rb`)

```ruby
config.concert_priority.default_ttl = 1800
config.concert_priority.resolver = ->(env) do
  env["PATH_INFO"].to_s.start_with?("/checkout") ? "checkout" : nil
end
```

class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :null_session

  def auth
    unless has_sufficient_params(['email', 'api_key'])
      return
    end

    email = params[:email].strip.downcase
    api_key = params[:api_key].strip

    user = User.where("email = ? AND api_key = ?", email, api_key).first
    unless user.present?
      render_error_json 'User not found'
      return
    end

    ttl = (30.minutes) / 60
    map = {email: email, api_key: api_key, ttl: ttl}
    token = generate_token(map, ttl)

    render_result_json token
  end

  def validate_user
    unless has_sufficient_params(['token'])
      return
    end

    user = authenticate_request!
    render_result_json user
  end

  protected

  def has_sufficient_params(params_list)
    params_list.each do |param|
      unless params[param].present?
        render_error_json "#{param} is mandatory".camelize
        return false
      end
    end
    return true
  end

  def render_result_json object
    response = {status: 'success', contents: object}
    render json: response
  end

  def render_success_json object
    response = get_success_json(object)
    render json: response
  end

  def get_success_json(object)
    response = {status: 'success', message: object}
  end

  def render_error_json message
    response = {status: 'error', message: message}
    render json: response, status: 500
  end

  def render_error_json_with_code error_code, message
    response = {status: 'error', error_code: error_code, message: message}
    render json: response
  end

  def render_unauthorised_json message
    response = {status: 'error', message: message}
    render json: response, status: 401
  end

  def get_response_as_json(controller, action)
    JSON.parse(render_to_string("#{controller}/#{action}.json.jbuilder"))
  end

  def validate_request(user)
    if user.access_locked?
      unlock_in = user.class.unlock_in / 60
      mins_since_lockout = ((DateTime.now.to_datetime - user.locked_at.to_datetime) * 24 * 60).to_i
      remaining_time = unlock_in - mins_since_lockout
      render_unauthorised_json "Your account has been locked. Please try after #{ remaining_time } mins."
      return false
    end
    return true
  end

  def validate_access(user, pin, increament = true)
    unless user.present?
      render_unauthorised_json 'Please enter valid credentials.'
      return false
    end

    unlock_in = user.class.unlock_in / 60
    if user.access_locked? == true
      mins_since_lockout = ((DateTime.now.to_datetime - user.locked_at.to_datetime) * 24 * 60).to_i
      remaining_time = unlock_in - mins_since_lockout
      render_unauthorised_json "Your account has been locked. Please try after #{ remaining_time } mins."
      return false
    end

    unless user.valid_password?(pin)
      user.failed_attempts += 1
      if user.failed_attempts > 4
        user.lock_access! unless user.access_locked?

        render_unauthorised_json "Your account has been locked. Please try after #{ unlock_in } mins."
        return false
      end
      user.save
      render_unauthorised_json 'Please enter valid credentials.'
      return false
    end
    user.sign_in_count += 1 if increament == true
    user.unlock_access!

    return true
  end

  def random_password
    key = 6.times.map { [*0..9].sample }.join
    return key
  end

  def authenticate_request!
    unless user_in_token?
      render_unauthorised_json "Not Authenticated"
      return
    end

    user = User.where(api_key: auth_token[:api_key], email: auth_token[:email]).first

    unless user.present?
      render_unauthorised_json "Not Authenticated"
      return
    end

    return user
  rescue JWT::VerificationError, JWT::DecodeError
    render_unauthorised_json "Not Authenticated"
    return
  end

  def generate_token(user, ttl)
    return JsonWebToken.encode(user) if user
  end

  def http_token
    @http_token ||= if request.headers['Authorization'].present?
      request.headers['Authorization'].split(' ').last
    end
  end

  def auth_token
    @auth_token ||= JsonWebToken.decode(http_token)
  end

  def user_in_token?
    if http_token && auth_token
      (auth_token[:api_key] && auth_token[:email])
    end
  end
end

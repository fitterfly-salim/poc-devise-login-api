class JsonWebToken
    def self.encode(payload, exp = 120)
        payload[:exp] = exp.minutes.from_now.to_i
        JWT.encode(payload, ENV["AUTH_SECRET"])
    end
  
    def self.decode(token)
        return HashWithIndifferentAccess.new(JWT.decode(token, ENV["AUTH_SECRET"])[0])
    rescue
        nil
    end
end
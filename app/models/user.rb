class User < ActiveRecord::Base

  before_create :update_api_key

  validates :email, presence: true
  validates :email, uniqueness: true

  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  def update_api_key
    self.api_key = 32.times.map { [*'A'..'Z', *'a'..'z', *'0'..'9'].sample }.join
  end
end

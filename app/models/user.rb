class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  validates :name, presence: true
  validates :username, uniqueness: true, presence: true

  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
  has_many :histories
end

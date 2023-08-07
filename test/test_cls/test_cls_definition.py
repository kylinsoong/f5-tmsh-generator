#!/usr/bin/python3

class Car:
    def __init__(self, make, model, year):
        self.make = make
        self.model = model
        self.year = year
        self.speed = 0

    def accelerate(self, acceleration):
        self.speed += acceleration

    def brake(self, deceleration):
        if self.speed >= deceleration:
            self.speed -= deceleration
        else:
            self.speed = 0

    def get_speed(self):
        return self.speed

def accelerate(car, speed):
    car.accelerate(speed)
    print("Current speed:", car.get_speed())

def brake(car, speed):
    car.brake(speed)
    print("Current speed:", car.get_speed())

my_car = Car("BYD", "Camry", 2022)

print("Init speed:", my_car.get_speed())

accelerate(my_car, 30)
accelerate(my_car, 20)

brake(my_car, 40)
brake(my_car, 15)

print("Final speed:", my_car.get_speed())

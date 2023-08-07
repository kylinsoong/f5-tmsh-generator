#!/usr/bin/python3

def external_function(name):
    print(name + " call external function.")

class Animal:
    def __init__(self, name):
        self.name = name
    
    def hello(self):
        print(self.name + " say hello")        

    def make_sound(self):
        pass

class Dog(Animal):
    def make_sound(self):
        print(self.name + " Woof!")

    def call_external_function(self):
        external_function(self.name)

class Cat(Animal):
    def __init__(self, name, color):
        super().__init__(name)
        self.color = color

    def show_color(self):
        print(self.color)

    def make_sound(self):
        print(self.name + " Meow!")

    def call_external_function(self):
        external_function(self.name)

class ChinaCat(Cat):
    def show_color(self):
        print(self.color)

dog = Dog("Buddy")
cat = Cat("Whiskers", "Black")

dog.hello()
dog.make_sound()
dog.call_external_function()

cat.hello()
cat.make_sound()
cat.call_external_function()
cat.show_color()

print(dog.name, cat.name, cat.color)
print(Cat.__name__, Cat.__dict__, Cat.__doc__)

print("-----")

t = ChinaCat("Boo", "Yellow")
t.show_color()

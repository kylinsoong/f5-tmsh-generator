 
import argparse
import os
import subprocess

parser = argparse.ArgumentParser(description='Convert Chinese text to ASCII')
parser.add_argument('input_file', help='path to input file')
parser.add_argument('output_file', help='path to output file')

args = parser.parse_args()

if not os.path.isfile(args.input_file):
    print('Input file does not exist')
    exit()

subprocess.call(['opencc', '-i', args.input_file, '-o', args.output_file])



import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from test import Test
import numpy as np
import os
import gc

from pylatex import Document, Section, Figure, NoEscape, Subsection

def generate_report(tests, program, is_loopback, calib_program, dut_host):
    geometry_options = {"right": "2cm", "left": "2cm"}
    fname = program.split('/')[-1] + '-tests'
    try:
        os.remove(fname + '.pdf')
    except OSError:
        pass
    
    doc = Document(fname, geometry_options=geometry_options)

    doc.append('Test results for %s\n' % program)
    doc.append('Calibration method: %s\n' % "loopback" if is_loopback else calib_program)
    doc.append('DUT host: %s\n' % dut_host)

    sorted_tests = sorted(tests, key = lambda test: len(test.expected_path))

    for i in range(len(sorted_tests)):
        times = sorted(tests[i].packets[0].times)
        runs = range(len(times))

	plt.figure(figsize=(16,5))
        plt.bar(runs, times)
	plt.xlim(runs[0], runs[-1] + 1)
        plt.xlabel('Run #')
        plt.ylabel('Time - calibration (microseconds) ')
        plt.title('Test times')
        with doc.create(Section('Test %d' % (i+1))):
	    with doc.create(Subsection('Expected path')):
	        for point in tests[i].expected_path:
	    	    if 'tbl_act' in point:
	    	        continue
	    	    doc.append(str(point) + '\n')

	    with doc.create(Subsection('Stats (time - calibration time in microseconds)')):
	        doc.append('Mean: %f\n' % np.mean(times))
	        doc.append('Std dev: %f\n' % np.std(times))
	        doc.append('Median: %f\n' % np.median(times))

            with doc.create(Figure(position='htbp')) as plot:
                plot.add_plot(width=NoEscape(r'1\textwidth'))

        plt.clf()
	plt.close()
	gc.collect()

    doc.generate_pdf(clean_tex=True)

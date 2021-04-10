extern crate cpython;

use cpython::{PyResult, Python, py_module_initializer, py_fn};
use itertools::Itertools;


py_module_initializer!(fast_compute, |py, m| {
    m.add(py, "__doc__", "This module is implemented in Rust.")?;
    m.add(py, "compute", py_fn!(py, compute(modulus: usize, k: usize)))?;
    Ok(())
});


fn compute(_py: Python, modulus: usize, k: usize) -> PyResult<(usize, Vec<usize>)> {
    // Computing amount of combinations we will have
    // to initate array (vector) of needed length.
    let mut set_size: usize = 0;
    let mut lengths: Vec<usize> = Vec::new();
    for subset in (0..modulus).combinations(k) {
        if subset.iter().sum::<usize>() % modulus == 1 {
            set_size += 1;
            lengths.push(subset.len())
        }
    };
    Ok((set_size, lengths))
}


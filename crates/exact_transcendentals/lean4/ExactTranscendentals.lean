-- ExactTranscendentals: Integer-only transcendental function formalization
-- Part of the QMNF ecosystem
--
-- All computations use bounded integers. No floating-point types.
-- Scale factor SCALE = 2^30 for CORDIC, 2^62 for AGM.

import ExactTranscendentals.Basic
import ExactTranscendentals.Cordic
import ExactTranscendentals.ContinuedFraction
import ExactTranscendentals.ExactRational
import ExactTranscendentals.Agm
import ExactTranscendentals.BinarySplitting
import ExactTranscendentals.Isqrt

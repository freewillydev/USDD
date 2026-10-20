use nalgebra::{DMatrix, DVector, SVD};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

const NEUTRAL: f64 = 0.5;
const CATCH_TOLERANCE: f64 = 0.2;
const NUMERICAL_TOLERANCE: f64 = 1e-10;
const SMOOTHING_ALPHA: f64 = 0.3;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ConsensusResult {
    pub outcomes: BTreeMap<[u8; 3], Option<f64>>,
    pub categorical_winners: BTreeMap<[u8; 3], Option<u16>>,
    pub first_loading: Vec<f64>,
    pub certainty: f64,
    pub reputations: BTreeMap<[u8; 20], f64>,
}

fn valid(value: f64) -> Result<f64, ()> {
    value.is_finite().then_some(value).ok_or(())
}

fn normalize(values: &DVector<f64>, zero_nan: bool) -> DVector<f64> {
    let mut out = values.clone();
    out.apply(|value| {
        *value = if zero_nan && value.is_nan() {
            0.0
        } else {
            value.abs()
        };
    });
    let mut sum = out.sum();
    if sum == 0.0 {
        out.fill(1.0);
        sum = out.sum();
    }
    out / sum
}

fn catch(value: f64) -> f64 {
    if value < NEUTRAL - CATCH_TOLERANCE / 2.0 {
        0.0
    } else if value > NEUTRAL + CATCH_TOLERANCE / 2.0 {
        1.0
    } else {
        NEUTRAL
    }
}

fn weighted_means(matrix: &DMatrix<f64>, weights: &DVector<f64>) -> (DVector<f64>, Vec<bool>) {
    let mut outcomes = DVector::zeros(matrix.ncols());
    let mut has_votes = vec![false; matrix.ncols()];
    for column in 0..matrix.ncols() {
        let mut sum = 0.0;
        let mut weight_sum = 0.0;
        for row in 0..matrix.nrows() {
            let vote = matrix[(row, column)];
            if !vote.is_nan() {
                sum += vote * weights[row];
                weight_sum += weights[row];
                has_votes[column] = true;
            }
        }
        outcomes[column] = if weight_sum > 0.0 {
            sum / weight_sum
        } else {
            NEUTRAL
        };
    }
    (outcomes, has_votes)
}

fn weighted_median(values: &DVector<f64>, weights: &DVector<f64>) -> Result<f64, ()> {
    if values.is_empty() || values.len() != weights.len() {
        return Err(());
    }
    let mut sorted: Vec<_> = values.iter().zip(weights.iter()).collect();
    sorted.sort_by(|left, right| left.0.partial_cmp(right.0).unwrap_or(Ordering::Equal));
    let total: f64 = weights.sum();
    if total <= 0.0 {
        return Err(());
    }
    let half = total / 2.0;
    let mut cumulative = 0.0;
    for (index, &(value, weight)) in sorted.iter().enumerate() {
        cumulative += weight;
        if cumulative >= half {
            return if (cumulative - half).abs() < NUMERICAL_TOLERANCE && index + 1 < sorted.len() {
                Ok((*value + *sorted[index + 1].0) / 2.0)
            } else {
                Ok(*value)
            };
        }
    }
    Ok(*sorted.last().ok_or(())?.0)
}

fn score_reflect(component: &DVector<f64>, reputation: &DVector<f64>) -> Result<DVector<f64>, ()> {
    if component.len() <= 2 {
        return Ok(component.clone());
    }
    let median = weighted_median(component, reputation)?;
    let mut adjusted = component.clone();
    for index in 0..adjusted.len() {
        let reflection = component[index] - median;
        if reflection > 0.0 {
            adjusted[index] -= reflection * 0.5;
        }
    }
    Ok(adjusted)
}

fn principal_component(
    matrix: &DMatrix<f64>,
    weights: &DVector<f64>,
) -> Result<(DVector<f64>, DVector<f64>), ()> {
    if matrix.nrows() != weights.len() || weights.sum() <= 0.0 {
        return Err(());
    }
    let mean = (matrix.transpose() * weights) / weights.sum();
    let mut centered = matrix.clone();
    for mut row in centered.row_iter_mut() {
        row -= &mean.transpose();
    }
    let mut weighted = DMatrix::zeros(centered.nrows(), centered.ncols());
    for (index, row) in centered.row_iter().enumerate() {
        weighted.set_row(index, &(row * weights[index]));
    }
    let covariance = (centered.transpose() * weighted) / weights.sum();
    let svd = SVD::new(covariance, true, false);
    let mut loading = svd.u.ok_or(())?.column(0).clone_owned();
    let sign = loading
        .iter()
        .copied()
        .find(|value| *value != 0.0)
        .map(f64::signum)
        .unwrap_or(1.0);
    if sign < 0.0 {
        loading = -loading;
    }
    let score = centered * &loading;
    Ok((score, loading))
}

fn reward_weights(
    matrix: &DMatrix<f64>,
    old: &DVector<f64>,
    participation: &DVector<f64>,
    participation_total: f64,
) -> Result<(DVector<f64>, DVector<f64>), ()> {
    let (score, loading) = principal_component(matrix, old)?;
    let mut new = old.clone();
    if score.abs().sum() != 0.0 {
        let option1 = &score + DVector::from_element(score.len(), score.min()).abs();
        let option2 = (&score - DVector::from_element(score.len(), score.max())).abs();
        let reflected1 = score_reflect(&option1, old)?;
        let reflected2 = score_reflect(&option2, old)?;
        let (means, _) = weighted_means(matrix, old);
        let caught = means.map(catch);
        let mut distance = DMatrix::zeros(matrix.nrows(), matrix.ncols());
        for row in 0..matrix.nrows() {
            for column in 0..matrix.ncols() {
                let vote = matrix[(row, column)];
                if !vote.is_nan() {
                    distance[(row, column)] = (vote - caught[column]).abs();
                }
            }
        }
        let mainstream = normalize(
            &loading.abs().map(|value| {
                if value > f64::EPSILON {
                    1.0 / value
                } else {
                    0.0
                }
            }),
            true,
        );
        let mut non_compliance = DVector::zeros(matrix.nrows());
        for row in 0..matrix.nrows() {
            for column in 0..matrix.ncols() {
                non_compliance[row] += distance[(row, column)] * mainstream[column];
            }
        }
        let max: f64 = non_compliance.max();
        let compliance = normalize(&non_compliance.map(|value| (value - max).abs()), true);
        let score1 = normalize(&reflected1, false);
        let score2 = normalize(&reflected2, false);
        let choice1: f64 = (&score1 - &compliance)
            .iter()
            .map(|value| value.powi(2))
            .sum();
        let choice2: f64 = (&score2 - &compliance)
            .iter()
            .map(|value| value.powi(2))
            .sum();
        let mean = old.mean();
        if mean > 0.0 {
            let scaled = old.map(|value| value / mean);
            let rep1 = normalize(&reflected1.component_mul(&scaled), false);
            let rep2 = normalize(&reflected2.component_mul(&scaled), false);
            new = if choice1 - choice2 < 0.0 { rep1 } else { rep2 };
        }
    }
    let normalized_old = normalize(old, true);
    let participation_sum = participation.sum();
    let relative = if participation_sum > f64::EPSILON {
        participation / participation_sum
    } else {
        DVector::from_element(matrix.nrows(), 1.0 / matrix.nrows() as f64)
    };
    let blended = new * participation_total + relative * (1.0 - participation_total);
    Ok((
        blended * SMOOTHING_ALPHA + normalized_old * (1.0 - SMOOTHING_ALPHA),
        loading,
    ))
}

fn round(value: f64, decimals: i32) -> f64 {
    let factor = 10_f64.powi(decimals);
    (value * factor).round() / factor
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn calculate(
    voters: &[[u8; 20]],
    decisions: &[[u8; 3]],
    votes: &BTreeMap<([u8; 20], [u8; 3]), f64>,
    reputation: &BTreeMap<[u8; 20], f64>,
    scaled: &BTreeSet<[u8; 3]>,
    categorical: &BTreeMap<[u8; 3], u16>,
) -> Result<ConsensusResult, ()> {
    if voters.is_empty() || decisions.is_empty() {
        return Err(());
    }
    let mut matrix = DMatrix::from_element(voters.len(), decisions.len(), f64::NAN);
    for (row, voter) in voters.iter().enumerate() {
        for (column, decision) in decisions.iter().enumerate() {
            if let Some(value) = votes.get(&(*voter, *decision)) {
                matrix[(row, column)] = valid(*value)?;
            }
        }
    }
    let mut categorical_winners = BTreeMap::new();
    for (column, decision) in decisions.iter().enumerate() {
        let Some(option_count) = categorical.get(decision).copied() else {
            continue;
        };
        let mut counts = BTreeMap::<u16, usize>::new();
        for row in 0..matrix.nrows() {
            let value = matrix[(row, column)];
            if !value.is_nan() {
                let index = value.round() as u16;
                if index <= option_count {
                    *counts.entry(index).or_default() += 1;
                }
            }
        }
        if counts.is_empty() {
            categorical_winners.insert(*decision, None);
            continue;
        }
        let maximum = counts.values().copied().max().unwrap_or(0);
        let winners: Vec<_> = counts
            .iter()
            .filter(|(_, count)| **count == maximum)
            .map(|(key, _)| *key)
            .collect();
        let winner = if winners.len() == 1 && winners[0] < option_count {
            winners[0]
        } else {
            option_count
        };
        for row in 0..matrix.nrows() {
            let value = matrix[(row, column)];
            if !value.is_nan() {
                matrix[(row, column)] = f64::from((value.round() as u16 == winner) as u8);
            }
        }
        categorical_winners.insert(*decision, Some(winner));
    }
    let mut old = DVector::from_iterator(
        voters.len(),
        voters
            .iter()
            .map(|voter| reputation.get(voter).copied().unwrap_or(0.0)),
    );
    let original_total = old.sum();
    if original_total > 0.0 {
        old /= original_total
    } else {
        old.fill(1.0 / voters.len() as f64)
    }
    let mut participation = DVector::zeros(voters.len());
    let mut cast = 0_usize;
    for row in 0..matrix.nrows() {
        let count = (0..matrix.ncols())
            .filter(|column| !matrix[(row, *column)].is_nan())
            .count();
        cast += count;
        participation[row] = count as f64 / matrix.ncols() as f64;
    }
    let participation_total = cast as f64 / (matrix.nrows() * matrix.ncols()) as f64;
    let (raw_means, has_votes) = weighted_means(&matrix, &old);
    let fill_values = raw_means.map(catch);
    for row in 0..matrix.nrows() {
        for column in 0..matrix.ncols() {
            if matrix[(row, column)].is_nan() {
                matrix[(row, column)] = fill_values[column]
            }
        }
    }
    let (smooth, loading) = reward_weights(&matrix, &old, &participation, participation_total)?;
    let mut decision_values = DVector::zeros(decisions.len());
    for column in 0..decisions.len() {
        if scaled.contains(&decisions[column]) {
            decision_values[column] = weighted_median(
                &DVector::from_iterator(matrix.nrows(), matrix.column(column).iter().copied()),
                &smooth,
            )?;
        } else {
            let weighted_sum: f64 = (0..matrix.nrows())
                .map(|row| matrix[(row, column)] * smooth[row])
                .sum();
            decision_values[column] = catch(weighted_sum / smooth.sum());
        }
    }
    let certainty = (0..decisions.len())
        .map(|column| {
            (0..matrix.nrows())
                .filter(|row| {
                    (decision_values[column] - matrix[(*row, column)]).abs() < NUMERICAL_TOLERANCE
                })
                .map(|row| smooth[row])
                .sum::<f64>()
        })
        .sum::<f64>()
        / decisions.len() as f64;
    let mut outcomes = BTreeMap::new();
    for (column, decision) in decisions.iter().enumerate() {
        let value = categorical_winners.get(decision).map_or_else(
            || has_votes[column].then(|| round(decision_values[column], 8)),
            |winner| {
                Some(match winner {
                    Some(index) if *index < categorical[decision] => f64::from(*index),
                    _ => NEUTRAL,
                })
            },
        );
        outcomes.insert(*decision, value);
    }
    let scale = if smooth.sum() > 0.0 && original_total > 0.0 {
        original_total / smooth.sum()
    } else {
        voters.len() as f64 * NEUTRAL
    };
    let mut reputations = BTreeMap::new();
    let mut maximum = None::<([u8; 20], f64)>;
    for (index, voter) in voters.iter().enumerate() {
        let value = round(smooth[index] * scale, 10);
        reputations.insert(*voter, value);
        if maximum.is_none_or(|(_, best)| value > best) {
            maximum = Some((*voter, value));
        }
    }
    let residual = original_total - reputations.values().sum::<f64>();
    if residual.abs() > 0.0 {
        let address = maximum.ok_or(())?.0;
        *reputations.get_mut(&address).ok_or(())? = round(reputations[&address] + residual, 10);
    }
    Ok(ConsensusResult {
        outcomes,
        categorical_winners,
        first_loading: loading.iter().copied().collect(),
        certainty,
        reputations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unanimous_binary_conserves_reputation() {
        let voters = [[1; 20], [2; 20], [3; 20]];
        let decisions = [[1, 0, 0]];
        let votes = voters
            .into_iter()
            .map(|voter| ((voter, decisions[0]), 1.0))
            .collect();
        let reputation = BTreeMap::from([([1; 20], 0.2), ([2; 20], 0.3), ([3; 20], 0.5)]);
        let result = calculate(
            &voters,
            &decisions,
            &votes,
            &reputation,
            &BTreeSet::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(result.outcomes[&decisions[0]], Some(1.0));
        assert!((result.reputations.values().sum::<f64>() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn categorical_tie_uses_inconclusive_sentinel() {
        let voters = [[1; 20], [2; 20]];
        let decisions = [[2, 0, 0]];
        let votes = BTreeMap::from([
            ((voters[0], decisions[0]), 0.0),
            ((voters[1], decisions[0]), 1.0),
        ]);
        let reputation = BTreeMap::from([([1; 20], 0.5), ([2; 20], 0.5)]);
        let result = calculate(
            &voters,
            &decisions,
            &votes,
            &reputation,
            &BTreeSet::new(),
            &BTreeMap::from([(decisions[0], 2)]),
        )
        .unwrap();
        assert_eq!(result.categorical_winners[&decisions[0]], Some(2));
        assert_eq!(result.outcomes[&decisions[0]], Some(0.5));
    }

    #[test]
    fn matches_pinned_native_mixed_consensus_vector() {
        let voters = [[1; 20], [2; 20], [3; 20], [4; 20]];
        let decisions = [[0, 0, 0], [0, 0, 1], [0, 0, 2]];
        let mut votes = BTreeMap::new();
        for (voter, values) in [
            (voters[0], [Some(1.0), Some(0.2), Some(0.0)]),
            (voters[1], [Some(1.0), Some(0.4), Some(1.0)]),
            (voters[2], [Some(0.0), None, Some(1.0)]),
            (voters[3], [Some(1.0), Some(0.8), Some(2.0)]),
        ] {
            for (decision, value) in decisions.iter().zip(values) {
                if let Some(value) = value {
                    votes.insert((voter, *decision), value);
                }
            }
        }
        let reputation = BTreeMap::from([
            (voters[0], 0.1),
            (voters[1], 0.2),
            (voters[2], 0.3),
            (voters[3], 0.4),
        ]);
        let result = calculate(
            &voters,
            &decisions,
            &votes,
            &reputation,
            &BTreeSet::from([decisions[1]]),
            &BTreeMap::from([(decisions[2], 3)]),
        )
        .unwrap();
        assert_eq!(
            result.outcomes,
            BTreeMap::from([
                (decisions[0], Some(1.0)),
                (decisions[1], Some(0.8)),
                (decisions[2], Some(1.0)),
            ])
        );
        assert_eq!(
            result.first_loading,
            vec![0.6682737974905866, -0.2175557128636369, -0.7113927490408546,]
        );
        assert_eq!(result.certainty, 0.5113176757620029);
        assert_eq!(
            result.reputations,
            BTreeMap::from([
                (voters[0], 0.0768181818),
                (voters[1], 0.21667779),
                (voters[2], 0.3892287909),
                (voters[3], 0.3172752373),
            ])
        );
        assert_eq!(result.categorical_winners[&decisions[2]], Some(1));
    }
}

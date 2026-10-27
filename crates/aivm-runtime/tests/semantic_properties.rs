//! สร้าง inputs ให้ตัวตรวจ ไม่เรียกโมเดลจริงใน property gate
use aivm_runtime::semantic::{SemanticTask, MAX_VALUES};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn sorting_preserves_order_members_and_duplicate_counts(values in prop::collection::vec(any::<i32>(), 0..=MAX_VALUES)) {
        let task = SemanticTask::Sort {values:values.clone()};
        let correct=task.solve().unwrap();
        prop_assert!(task.check(&correct.to_string()).is_ok());
        let mut changed:Vec<i32>=serde_json::from_value(correct).unwrap();
        if !changed.is_empty() {
            changed.pop();
            prop_assert!(task.check(&serde_json::to_string(&changed).unwrap()).is_err());
        }
        let mut duplicated=values.clone();
        if !duplicated.is_empty() {
            duplicated.push(duplicated[0]); duplicated.sort_unstable();
            prop_assert!(task.check(&serde_json::to_string(&duplicated).unwrap()).is_err());
        }
        let mut descending=values; descending.sort_unstable_by(|a,b| b.cmp(a));
        if descending.windows(2).any(|w|w[0]>w[1]) {
            prop_assert!(task.check(&serde_json::to_string(&descending).unwrap()).is_err());
        }
    }

    #[test]
    fn signed_addition_rejects_overflow_and_wrong_results(left in any::<i32>(), right in any::<i32>()) {
        let task=SemanticTask::CAdd{left,right};
        match left.checked_add(right) {
            None => { prop_assert!(task.validate().is_err()); prop_assert!(task.program_source().is_err()); }
            Some(expected) => {
                prop_assert!(task.check(&expected.to_string()).is_ok());
                let wrong=if expected==i32::MAX {expected-1} else {expected+1};
                prop_assert!(task.check(&wrong.to_string()).is_err());
                let quoted = format!("\"{expected}\"");
                prop_assert!(task.check(&quoted).is_err());
            }
        }
    }
}

#[test]
fn original_failures_and_edge_cases_remain_regressions() {
    let sort = SemanticTask::Sort {
        values: vec![3, -2, 3, 0],
    };
    assert!(sort.check("[0,-2,3,3]").is_err());
    let add = SemanticTask::CAdd { left: -8, right: 3 };
    assert!(add.check("11").is_err());
    for raw in [
        "false",
        "-5.0",
        "{\"result\":-5}",
        "```json\n-5\n```",
        "-5 -5",
    ] {
        assert!(add.check(raw).is_err());
    }
    let empty = SemanticTask::Sort { values: vec![] };
    assert!(empty.check("[]").is_ok());
    assert!(empty.check("[0]").is_err());
    let bounds = SemanticTask::Sort {
        values: vec![i32::MAX, i32::MIN, i32::MIN],
    };
    assert!(bounds
        .check(&format!("[{},{},{}]", i32::MIN, i32::MIN, i32::MAX))
        .is_ok());
    assert!(SemanticTask::CAdd {
        left: i32::MIN,
        right: -1
    }
    .validate()
    .is_err());
    assert!(SemanticTask::Sort {
        values: vec![0; 65]
    }
    .validate()
    .is_err());
    assert!(serde_json::from_str::<SemanticTask>(
        r#"{"kind":"c_add","left":1,"right":2,"verified":true}"#
    )
    .is_err());
}

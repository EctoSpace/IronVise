use glib::variant::ToVariant;

#[test]
fn string_iterator_c_out_parameter_is_written_in_optimized_builds() {
    let v = ["zero", "one", "two", "three"].to_variant();
    let mut it = v.array_iter_str().unwrap();
    assert_eq!(it.next(), Some("zero"));
    assert_eq!(it.next_back(), Some("three"));
    assert_eq!(it.nth(1), Some("two"));
    assert_eq!(it.next(), None);
    assert_eq!(v.array_iter_str().unwrap().last(), Some("three"));
    assert_eq!(v.array_iter_str().unwrap().nth_back(1), Some("two"));
}

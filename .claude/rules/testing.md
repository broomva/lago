# Testing Rules

## Test Runner

**`cargo test`** is the standard test runner.

```bash
cargo test --workspace          # Run all tests
cargo test -p lago-core         # Run specific crate tests
cargo test -p lago-journal      # Run journal tests
```

## Test Structure

- **Unit Tests**: Place inside the same file or a `tests` module within the file.
  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;

      #[test]
      fn it_works() {
          assert_eq!(2 + 2, 4);
      }
  }
  ```

- **Integration Tests**: Place in `tests/` directory at the crate root.

## Mocking

- Use traits (`Journal`, `SseFormat`) to allow dependency injection.
- Implement mocks manually (preferred for simplicity over `mockall`).
- Use `tokio::test` for async tests.

## Coverage Requirements

- All new features require tests.
- Core logic in `lago-core`, `lago-journal`, and `lago-store` must be well-tested.
- Run `cargo test --workspace` before committing.
- Use `#[tokio::test]` for async tests involving redb or network I/O.

const validatePassword = (password = "") => {
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasMinLength = password.length >= 6;

  return {
    isValid: hasUppercase && hasLowercase && hasMinLength,
    errors: [
      !hasUppercase && "Must have an uppercase letter",
      !hasLowercase && "Must have a lowercase letter",
      !hasMinLength && "Length must be at least 6 characters",
    ].filter(Boolean),
  };
};

module.exports = {
  validatePassword,
};

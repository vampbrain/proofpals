export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

export function validateGenre(genre: string): boolean {
  const validGenres = ['news', 'research', 'music', 'video', 'literature', 'art'];
  return validGenres.includes(genre);
}

export function sanitizeInput(input: string): string {
  return input.trim().replace(/[<>]/g, '');
}


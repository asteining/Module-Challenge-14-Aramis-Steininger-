import { JwtPayload, jwtDecode } from 'jwt-decode';

interface DecodedToken extends JwtPayload {
  exp?: number;
  iat?: number;
  [key: string]: unknown;
}

class AuthService {
  // Returns the decoded token or null if no token is found
  getProfile() {
    const token = this.getToken();
    return token ? jwtDecode<DecodedToken>(token) : null;
  }

  // Returns true if the user is logged in (i.e. token exists and is not expired)
  loggedIn() {
    const token = this.getToken();
    return token !== '' && !this.isTokenExpired(token);
  }
  
  // Checks whether the token is expired
  isTokenExpired(token: string): boolean {
    try {
      const decoded = jwtDecode<DecodedToken>(token);
      if (decoded.exp) {
        // jwt exp is in seconds, so compare with current time in seconds
        return decoded.exp < Date.now() / 1000;
      }
      return false;
    } catch (error) {
      // If an error occurs during decoding, assume the token is invalid/expired
      return true;
    }
  }

  // Retrieves the token from localStorage
  getToken(): string {
    return localStorage.getItem('token') || '';
  }

  // Saves the token to localStorage and redirects to the home page
  login(idToken: string) {
    localStorage.setItem('token', idToken);
    window.location.href = '/';
  }

  // Removes the token from localStorage and redirects to the login page
  logout() {
    localStorage.removeItem('token');
    window.location.href = '/login';
  }
}

export default new AuthService();
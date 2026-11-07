export interface SessionUser {
  username: string;
  role: string;
}

export function sessionAfterStatus(session: SessionUser | null, status: number): SessionUser | null {
  if (status === 401) {
    return null;
  }
  return session;
}

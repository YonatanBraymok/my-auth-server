// Define a User (model) and export it for use in other parts of the application
export interface User {
    username: string;
    password: string;
}

export const users: User[] = []; // In-memory array to store users
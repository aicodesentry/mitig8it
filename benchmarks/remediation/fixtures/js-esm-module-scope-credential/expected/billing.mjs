// Billing settings, read once at import by every module that charges a card.
export const region = 'eu-west-1';
export const paymentSecret = process.env.PAYMENT_SECRET;
export const retries = 3;

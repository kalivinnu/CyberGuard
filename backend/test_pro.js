const levenshtein = (a, b) => {
  const tmp = [];
  for (let i = 0; i <= a.length; i++) { tmp[i] = [i]; }
  for (let j = 0; j <= b.length; j++) { tmp[0][j] = j; }
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      tmp[i][j] = Math.min(
        tmp[i - 1][j] + 1,
        tmp[i][j - 1] + 1,
        tmp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return tmp[a.length][b.length];
};

const TOP_BRANDS = ['google', 'facebook', 'paypal', 'amazon'];

function test(hostname) {
    const name = hostname.split('.')[0].toLowerCase();
    let result = null;
    for (const brand of TOP_BRANDS) {
        const dist = levenshtein(name, brand);
        if (dist > 0 && dist <= 2 && name.length >= 4) {
            result = { brand, dist };
            break;
        }
    }
    console.log(`Hostname: ${hostname} -> Result: ${JSON.stringify(result)}`);
}

test('g00gle.com');
test('paypa1.com');
test('amazn.de');
test('facebook-secure.host');
test('mybrand.com');

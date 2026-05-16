const dictionary = {
  lat: "KOMETAXPBHop", // Latin
  cyr: "КОМЕТАХРВНор", // Cyrillic
  ell: "ΚΟΜΕΤΑΧΡΒΗορ", // Greek
};

// Build lookup: char -> {setName, index}
function buildLookupTableFrom(dict) {
  const lookup = new Map();
  for (const [setName, chars] of Object.entries(dict)) {
    for (let i = 0; i < chars.length; i++) {
      lookup.set(chars[i], {setName, index: i});
    }
  }
  return lookup;
}

const flip = (text, targetSet = "cyr") => {
  const lookupTable = buildLookupTableFrom(dictionary);
  let result = "";

  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const info = lookupTable.get(char);

    if (info && dictionary[targetSet]) {
      // Replace with equivalent char from target set
      result += dictionary[targetSet][info.index];
    } else {
      // Keep original if not in dictionary
      result += char;
    }
  }
  return result;
};
